# SKILL: Cloud Security Assessment (AWS/Azure/GCP)

## Description
Cloud infrastructure security assessment methodology covering misconfigurations, IAM issues, and service exploitation.

## Trigger Phrases
cloud, aws, azure, gcp, s3, iam, lambda, ec2, storage, kubernetes, k8s, cloud pentest

## Methodology

### Phase 1: Reconnaissance
1. Enumerate S3 buckets: `aws s3 ls s3://<bucket> --no-sign-request`
2. Check for public snapshots: `aws ec2 describe-snapshots --restorable-by-user-ids all`
3. Azure blob enumeration: `https://<storage>.blob.core.windows.net/<container>?restype=container&comp=list`
4. GCP bucket check: `gsutil ls gs://<bucket>`
5. Subdomain enumeration for cloud endpoints

### Phase 2: IAM Exploitation
1. Enumerate IAM: `aws iam list-users`, `aws iam list-roles`
2. Check for overprivileged roles: `aws iam list-attached-role-policies --role-name <role>`
3. STS assume role: `aws sts assume-role --role-arn <arn> --role-session-name test`
4. Instance metadata SSRF: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
5. Azure managed identity: `curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token"`

### Phase 3: Service Exploitation
1. **Lambda**: Check for environment variable secrets, function URL exposure
2. **EC2**: User-data scripts with credentials, security groups
3. **RDS**: Public snapshots, weak authentication
4. **ECS/EKS**: Container escape, service account abuse
5. **Azure Key Vault**: Access policy misconfigs

### Phase 4: Privilege Escalation
1. IAM policy enumeration: `enumerate-iam` tool
2. AWS privesc paths: pacu framework
3. Azure: Check for Contributor/Owner role assignments
4. GCP: Check for `iam.serviceAccountTokenCreator` role
