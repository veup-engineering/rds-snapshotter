
# RDS Snapshot All

A simple Python script to create **RDS snapshots across all AWS regions** in your account.  
Runs directly in **AWS CloudShell** with no external dependencies beyond boto3.

## Features

-   Scans all opted-in AWS regions for RDS instances
    
-   Creates DB snapshots for standalone RDS instances
    
-   Creates cluster snapshots once per Aurora cluster
    
-   Skips read replicas by default (optional flag to include them)
    
-   Auto-tags snapshots with `CreatedBy=CloudShellScript` and account ID
    
-   Snapshot names are timestamped to avoid collisions
    
-   Prints a summary of created, skipped, and errored snapshots

## Usage

1.  Open **AWS CloudShell** in your AWS account.
    
2.  Clone this repository or copy the script:
    
    `git clone https://github.com/veup-engineering/rds-snapshotter.git`

3.  Change into the RDS Snapshot directory:
   
   `cd rds-snapshotter`

4.  Create a virtual environment:

    `python3 -m venv rds-env`

5.  Activate the virtual environment:

    `source rds-env/bin/activate`

6. Install boto3:

    `pip install boto3`
    
7.  Run the script:
    
    `python3 rds_snap_all.py` 
    
## Examples

Snapshot all RDS instances and Aurora clusters across all regions:

`python3 rds_snap_all.py` 

Snapshot only in `us-east-1` and `ca-central-1`:

`python3 rds_snap_all.py --regions us-east-1,ca-central-1` 

Include read replicas:

`python3 rds_snap_all.py --include-replicas` 

Custom snapshot prefix and tags:

`python3 rds_snap_all.py --prefix nightly --tag Env=Prod --tag Owner=DevOps` 

## IAM Permissions

Your CloudShell user/role must allow these actions:

-   `rds:DescribeDBInstances`
    
-   `rds:CreateDBSnapshot`
    
-   `rds:CreateDBClusterSnapshot`
    
-   `rds:AddTagsToResource`
    
-   `ec2:DescribeRegions`
    
-   `sts:GetCallerIdentity`
    

Example inline policy:

    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [
          "rds:DescribeDBInstances",
          "rds:CreateDBSnapshot",
          "rds:CreateDBClusterSnapshot",
          "rds:AddTagsToResource",
          "ec2:DescribeRegions",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      }]
    }


## Notes

-   The script does not wait for snapshots to finish, it only initiates them.
    
-   Aurora clusters: only one cluster snapshot per `DBClusterIdentifier` is created.
    
-   Read replicas are skipped unless you pass `--include-replicas`.
    
-   Snapshot IDs are timestamped in UTC, e.g. `autosnap-db-mydb-20250909-053000`.
    
-   Tags are attached both at snapshot creation and via `AddTagsToResource` for consistency.
