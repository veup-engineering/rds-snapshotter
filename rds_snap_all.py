#!/usr/bin/env python3
import argparse
import datetime as dt
import sys
from typing import Dict, List, Set

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# ------------- CLI -------------
parser = argparse.ArgumentParser(
    description="Create RDS snapshots for all DB instances (and Aurora clusters) across all opted-in regions."
)
parser.add_argument(
    "--include-replicas",
    action="store_true",
    help="Also snapshot read replicas (default: skip)."
)
parser.add_argument(
    "--regions",
    help="Comma-separated list of regions to scan (default: all opted-in regions)."
)
parser.add_argument(
    "--prefix",
    default="autosnap",
    help="Snapshot name prefix (default: autosnap)."
)
parser.add_argument(
    "--tag",
    action="append",
    default=[],
    help="Add tag Key=Value to snapshots (can be specified multiple times)."
)
parser.add_argument(
    "--filter-tag",
    action="append", 
    default=[],
    help="Only snapshot RDS instances with this tag Key=Value (can be specified multiple times)."
)
args = parser.parse_args()

# ------------- Setup -------------
cfg = Config(
    retries={"max_attempts": 10, "mode": "standard"},
    user_agent_extra="rds-snap-all/1.0"
)

session = boto3.Session()
sts = session.client("sts", config=cfg)
account = sts.get_caller_identity()["Account"]

ec2 = session.client("ec2", config=cfg)
if args.regions:
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
else:
    # Only regions you can actually use: opted-in or not-required
    reg_resp = ec2.describe_regions(AllRegions=True)
    regions = [
        r["RegionName"]
        for r in reg_resp["Regions"]
        if r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")
    ]

now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")

# Prepare tags for snapshots
tags = [{"Key": "CreatedBy", "Value": "CloudShellScript"},
        {"Key": "AccountId", "Value": account}]
for t in args.tag:
    if "=" in t:
        k, v = t.split("=", 1)
        if k:
            tags.append({"Key": k, "Value": v})

# Prepare filter tags
filter_tags = {}
for t in args.filter_tag:
    if "=" in t:
        k, v = t.split("=", 1)
        if k:
            filter_tags[k] = v

def get_resource_tags(rds_client, resource_arn: str) -> Dict[str, str]:
    """Get tags for an RDS resource."""
    try:
        resp = rds_client.list_tags_for_resource(ResourceName=resource_arn)
        return {tag["Key"]: tag["Value"] for tag in resp.get("TagList", [])}
    except ClientError as e:
        print(f"Warning: Could not get tags for {resource_arn}: {e}")
        return {}

def matches_filter_tags(resource_tags: Dict[str, str], filter_tags: Dict[str, str]) -> bool:
    """Check if resource tags match all filter criteria."""
    if not filter_tags:
        return True  # No filters means include all
    
    for key, value in filter_tags.items():
        if resource_tags.get(key) != value:
            return False
    return True

def tag_arn_for_snapshot(region: str, snapshot_id: str, cluster: bool) -> str:
    # RDS snapshot ARNs:
    #   db snapshot: arn:aws:rds:<region>:<acct>:snapshot:<snapshot-id>
    #   cluster snapshot: arn:aws:rds:<region>:<acct>:cluster-snapshot:<snapshot-id>
    snap_type = "cluster-snapshot" if cluster else "snapshot"
    return f"arn:aws:rds:{region}:{account}:{snap_type}:{snapshot_id}"

def db_instance_arn(region: str, db_id: str) -> str:
    return f"arn:aws:rds:{region}:{account}:db:{db_id}"

def db_cluster_arn(region: str, cluster_id: str) -> str:
    return f"arn:aws:rds:{region}:{account}:cluster:{cluster_id}"

created = []
skipped = []
errors = []

# ------------- Work per region -------------
for region in regions:
    rds = session.client("rds", region_name=region, config=cfg)
    print(f"\n=== Region: {region} ===")
    
    if filter_tags:
        print(f"Filtering for tags: {filter_tags}")

    # Collect DB instances
    instances: List[Dict] = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        instances.extend(page.get("DBInstances", []))

    if not instances:
        print("No DB instances found.")
        continue

    # Partition: cluster-backed (Aurora) vs standalone
    cluster_ids: Set[str] = set()
    standalone_instances: List[Dict] = []

    for inst in instances:
        # Skip replicas unless requested
        if (not args.include_replicas) and inst.get("ReadReplicaSourceDBInstanceIdentifier"):
            skipped.append((region, inst["DBInstanceIdentifier"], "read-replica"))
            continue

        # Check if instance matches filter tags
        if filter_tags:
            inst_arn = db_instance_arn(region, inst["DBInstanceIdentifier"])
            inst_tags = get_resource_tags(rds, inst_arn)
            if not matches_filter_tags(inst_tags, filter_tags):
                skipped.append((region, inst["DBInstanceIdentifier"], "tag-filter-mismatch"))
                print(f"• Skipped {inst['DBInstanceIdentifier']}: doesn't match tag filter")
                continue

        if inst.get("DBClusterIdentifier"):
            cluster_ids.add(inst["DBClusterIdentifier"])
        else:
            standalone_instances.append(inst)

    # For clusters, we also need to check cluster-level tags
    filtered_cluster_ids = set()
    if cluster_ids and filter_tags:
        for cid in cluster_ids:
            cluster_arn = db_cluster_arn(region, cid)
            cluster_tags = get_resource_tags(rds, cluster_arn)
            if matches_filter_tags(cluster_tags, filter_tags):
                filtered_cluster_ids.add(cid)
            else:
                skipped.append((region, cid, "cluster-tag-filter-mismatch"))
                print(f"• Skipped cluster {cid}: doesn't match tag filter")
    else:
        filtered_cluster_ids = cluster_ids

    # Create cluster snapshots (one per DBClusterIdentifier)
    if filtered_cluster_ids:
        for cid in sorted(filtered_cluster_ids):
            snap_id = f"{args.prefix}-cluster-{cid}-{now_utc}"
            try:
                resp = rds.create_db_cluster_snapshot(
                    DBClusterSnapshotIdentifier=snap_id,
                    DBClusterIdentifier=cid,
                    Tags=tags
                )
                arn = tag_arn_for_snapshot(region, snap_id, cluster=True)
                # Extra tagging (some orgs prefer AddTagsToResource anyway)
                rds.add_tags_to_resource(ResourceName=arn, Tags=tags)
                created.append((region, "cluster", cid, snap_id))
                print(f"✔ Created cluster snapshot {snap_id} for {cid}")
            except ClientError as e:
                if e.response["Error"]["Code"] == "DBClusterSnapshotAlreadyExistsFault":
                    skipped.append((region, cid, "cluster-snapshot-exists"))
                    print(f"• Skipped (exists): cluster {cid} -> {snap_id}")
                else:
                    errors.append((region, cid, str(e)))
                    print(f"✖ Error (cluster {cid}): {e}")

    # Create standalone DB instance snapshots
    for inst in standalone_instances:
        dbid = inst["DBInstanceIdentifier"]
        snap_id = f"{args.prefix}-db-{dbid}-{now_utc}"
        try:
            resp = rds.create_db_snapshot(
                DBSnapshotIdentifier=snap_id,
                DBInstanceIdentifier=dbid,
                Tags=tags
            )
            arn = tag_arn_for_snapshot(region, snap_id, cluster=False)
            rds.add_tags_to_resource(ResourceName=arn, Tags=tags)
            created.append((region, "db", dbid, snap_id))
            print(f"✔ Created DB snapshot {snap_id} for {dbid}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("DBSnapshotAlreadyExists", "DBSnapshotAlreadyExistsFault"):
                skipped.append((region, dbid, "db-snapshot-exists"))
                print(f"• Skipped (exists): {dbid} -> {snap_id}")
            elif code == "InvalidDBInstanceState":
                skipped.append((region, dbid, "invalid-state"))
                print(f"• Skipped (state): {dbid} not in a snapshot-eligible state")
            else:
                errors.append((region, dbid, str(e)))
                print(f"✖ Error (db {dbid}): {e}")

# ------------- Summary -------------
print("\n===== Summary =====")
print(f"Created: {len(created)} snapshot(s)")
for r, kind, target, snap in created:
    print(f"  [{r}] {kind}: {target} -> {snap}")
print(f"Skipped: {len(skipped)}")
for r, target, why in skipped:
    print(f"  [{r}] {target}: {why}")
if errors:
    print(f"Errors: {len(errors)}")
    for r, target, err in errors:
        print(f"  [{r}] {target}: {err}")
else:
    print("Errors: 0")
