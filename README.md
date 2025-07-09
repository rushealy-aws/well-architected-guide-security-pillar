# AWS Well-Architected Security Review Guide

A comprehensive step-by-step guide for performing a Well-Architected Review focused on the Security pillar using the AWS Well-Architected Tool.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Understanding the Security Pillar](#understanding-the-security-pillar)
4. [Security Design Principles](#security-design-principles)
5. [Security Domains Overview](#security-domains-overview)
6. [Pre-Review Assessment](#pre-review-assessment)
7. [Review Planning](#review-planning)
8. [Step-by-Step Review Process](#step-by-step-review-process)
9. [Testing and Validation](#testing-and-validation)
10. [Troubleshooting Common Issues](#troubleshooting-common-issues)
11. [Post-Review Implementation](#post-review-implementation)
12. [Additional Resources](#additional-resources)

## Overview

The AWS Well-Architected Framework Security pillar encompasses the ability to protect data, systems, and assets to take advantage of cloud technologies to improve your security. This guide provides a comprehensive approach to conducting security reviews using the AWS Well-Architected Tool, helping you identify security gaps and implement best practices.

### Key Benefits of Security Reviews

- **Risk Reduction**: Identify and mitigate security vulnerabilities before they can be exploited
- **Compliance Alignment**: Ensure adherence to regulatory requirements and industry standards
- **Defense in Depth**: Implement multiple layers of security controls
- **Incident Preparedness**: Establish robust incident response and recovery procedures
- **Continuous Improvement**: Build a culture of security awareness and ongoing enhancement

### Review Scope

This guide covers the seven key areas of the Security pillar:
- **Security Foundations**: Organizational security requirements and governance
- **Identity and Access Management**: Authentication, authorization, and privilege management
- **Detection**: Logging, monitoring, and threat detection
- **Infrastructure Protection**: Network and host-level security controls
- **Data Protection**: Encryption, classification, and data lifecycle management
- **Incident Response**: Preparation, detection, analysis, and recovery procedures
- **Application Security**: Secure development practices and application-level controls

**Important Note**: Security is a shared responsibility between AWS and customers. This guide focuses on customer responsibilities while leveraging AWS security services and capabilities.

## Prerequisites

### Technical Requirements

1. **AWS Account and Access**
   - Active AWS account with workloads deployed
   - Administrative access to AWS services and configurations
   - Access to AWS Well-Architected Tool
   - CloudTrail, Config, and other security services enabled

2. **Security Knowledge Base**
   - Current security policies and procedures
   - Compliance and regulatory requirements
   - Risk assessment and threat modeling documentation
   - Incident response procedures and contacts

3. **Infrastructure Documentation**
   - Network architecture and security group configurations
   - IAM policies, roles, and user access patterns
   - Data classification and handling procedures
   - Application architecture and security controls

### Skills and Knowledge

1. **Technical Expertise**
   - AWS security services and best practices
   - Identity and access management concepts
   - Network security and encryption technologies
   - Security monitoring and incident response
   - Compliance frameworks and requirements

2. **Organizational Understanding**
   - Business risk tolerance and security requirements
   - Regulatory and compliance obligations
   - Data sensitivity and classification schemes
   - Incident response and business continuity plans

### Pre-Review Checklist

- [ ] Enable AWS CloudTrail in all regions and accounts
- [ ] Configure AWS Config for compliance monitoring
- [ ] Set up AWS Security Hub for centralized security findings
- [ ] Document current security policies and procedures
- [ ] Identify data classification and handling requirements
- [ ] Review existing incident response procedures
- [ ] Gather compliance and regulatory requirements
- [ ] Prepare security team availability for review sessions

## Understanding the Security Pillar

### Security Definition

**Security** encompasses the ability to protect data, systems, and assets to take advantage of cloud technologies to improve your security. This includes:

- **Confidentiality**: Ensuring information is accessible only to authorized individuals
- **Integrity**: Maintaining accuracy and completeness of data and systems
- **Availability**: Ensuring systems and data are accessible when needed
- **Authentication**: Verifying the identity of users and systems
- **Authorization**: Controlling access to resources based on verified identity
- **Non-repudiation**: Ensuring actions cannot be denied by the actor

### Shared Responsibility Model

#### AWS Responsibilities (Security OF the Cloud)
- Physical security of data centers
- Hardware and software infrastructure
- Network infrastructure and virtualization
- Managed service security configurations
- Global infrastructure security

#### Customer Responsibilities (Security IN the Cloud)
- Operating system and network configuration
- Platform and application management
- Identity and access management
- Data encryption and protection
- Network traffic protection
- Security group and firewall configuration

### Security vs. Other Pillars

#### Security and Reliability
- Security incidents can impact system availability
- Security controls must not compromise system reliability
- Incident response procedures must maintain business continuity

#### Security and Performance
- Security controls may impact system performance
- Encryption and monitoring add computational overhead
- Balance security requirements with performance needs

#### Security and Cost
- Security investments require cost-benefit analysis
- Automated security controls reduce operational costs
- Security incidents can have significant financial impact

## Security Design Principles

### 1. Implement a Strong Identity Foundation

**Principle**: Implement the principle of least privilege and enforce separation of duties with appropriate authorization for each interaction with AWS resources.

**Implementation Strategies:**
- **Centralized Identity Management**: Use AWS IAM Identity Center (formerly SSO) or external identity providers
- **Least Privilege Access**: Grant minimum permissions necessary for job functions
- **Separation of Duties**: Distribute critical functions across multiple individuals
- **Regular Access Reviews**: Periodically review and validate access permissions

**AWS Services:**
- AWS IAM for access management
- AWS IAM Identity Center for centralized identity
- AWS Organizations for multi-account governance
- AWS CloudTrail for access auditing

### 2. Maintain Traceability

**Principle**: Monitor, alert, and audit actions and changes to your environment in real time.

**Implementation Strategies:**
- **Comprehensive Logging**: Enable logging across all AWS services and applications
- **Real-time Monitoring**: Implement automated monitoring and alerting
- **Audit Trails**: Maintain detailed records of all system and user activities
- **Automated Response**: Use automation to respond to security events

**AWS Services:**
- AWS CloudTrail for API logging
- Amazon CloudWatch for monitoring and alerting
- AWS Config for configuration change tracking
- AWS Security Hub for centralized security findings

### 3. Apply Security at All Layers

**Principle**: Apply a defense in depth approach with multiple security controls at all layers.

**Implementation Strategies:**
- **Network Security**: Implement VPCs, security groups, and NACLs
- **Host Security**: Secure operating systems and applications
- **Application Security**: Implement secure coding practices
- **Data Security**: Encrypt data at rest and in transit

**AWS Services:**
- Amazon VPC for network isolation
- AWS WAF for application protection
- AWS Shield for DDoS protection
- AWS KMS for encryption key management

### 4. Automate Security Best Practices

**Principle**: Use automated software-based security mechanisms to improve scalability and cost-effectiveness.

**Implementation Strategies:**
- **Infrastructure as Code**: Define security controls in code templates
- **Automated Compliance**: Use services to automatically check compliance
- **Security Automation**: Implement automated remediation for common issues
- **Continuous Security**: Integrate security into CI/CD pipelines

**AWS Services:**
- AWS CloudFormation for infrastructure as code
- AWS Config Rules for automated compliance checking
- AWS Systems Manager for automated remediation
- AWS CodePipeline for secure CI/CD

### 5. Protect Data in Transit and at Rest

**Principle**: Classify data by sensitivity levels and use appropriate protection mechanisms.

**Implementation Strategies:**
- **Data Classification**: Implement data classification schemes
- **Encryption**: Use encryption for sensitive data at rest and in transit
- **Key Management**: Implement proper encryption key lifecycle management
- **Access Controls**: Restrict data access based on classification

**AWS Services:**
- AWS KMS for key management
- AWS Certificate Manager for SSL/TLS certificates
- Amazon S3 encryption for data at rest
- AWS PrivateLink for private connectivity

### 6. Keep People Away from Data

**Principle**: Reduce or eliminate direct access to data to minimize human error and mishandling.

**Implementation Strategies:**
- **Automated Processing**: Use automated systems for data processing
- **API-based Access**: Provide programmatic access instead of direct data access
- **Role-based Access**: Use service roles instead of user credentials
- **Data Masking**: Implement data masking for non-production environments

**AWS Services:**
- AWS Lambda for serverless processing
- Amazon API Gateway for controlled API access
- AWS IAM roles for service-to-service authentication
- AWS Glue for automated data processing

### 7. Prepare for Security Events

**Principle**: Prepare for incidents with proper incident management and investigation processes.

**Implementation Strategies:**
- **Incident Response Plan**: Develop and maintain incident response procedures
- **Security Playbooks**: Create detailed response procedures for common scenarios
- **Regular Drills**: Conduct incident response exercises and simulations
- **Forensic Capabilities**: Implement tools and processes for security investigations

**AWS Services:**
- AWS Security Hub for centralized incident management
- Amazon GuardDuty for threat detection
- AWS Systems Manager for incident response automation
- AWS CloudFormation for rapid environment recreation

## Security Domains Overview

### Security Foundations

**Focus Areas:**
- Organizational security requirements and governance
- Security policies and procedures
- Compliance and regulatory requirements
- Security training and awareness

**Key Questions:**
- How do you securely operate your workload?
- How do you manage security requirements?

### Identity and Access Management (IAM)

**Focus Areas:**
- User identity and authentication
- Privilege management and authorization
- Credential lifecycle management
- Access monitoring and auditing

**Key Questions:**
- How do you manage identities for people and machines?
- How do you manage permissions for people and machines?

### Detection

**Focus Areas:**
- Security monitoring and logging
- Threat detection and analysis
- Incident alerting and notification
- Security metrics and reporting

**Key Questions:**
- How do you detect and investigate security events?
- How do you prepare for incident response?

### Infrastructure Protection

**Focus Areas:**
- Network security and segmentation
- Compute resource protection
- Service-level security controls
- Boundary protection mechanisms

**Key Questions:**
- How do you protect your network resources?
- How do you protect your compute resources?

### Data Protection

**Focus Areas:**
- Data classification and handling
- Encryption and key management
- Data backup and recovery
- Data lifecycle management

**Key Questions:**
- How do you classify your data?
- How do you protect your data at rest?
- How do you protect your data in transit?

### Incident Response

**Focus Areas:**
- Incident response planning and preparation
- Detection and analysis procedures
- Containment and eradication processes
- Recovery and post-incident activities

**Key Questions:**
- How do you anticipate, respond to, and recover from incidents?

### Application Security

**Focus Areas:**
- Secure development lifecycle
- Application-level security controls
- Code security and vulnerability management
- Third-party component security

**Key Questions:**
- How do you design and implement application security?
- How do you automate application security testing?
## Pre-Review Assessment

### Current Security Posture Analysis

#### 1. Security Configuration Inventory

**AWS Security Services Assessment:**
```bash
#!/bin/bash
# security_services_assessment.sh

echo "=== AWS Security Services Assessment ==="

# Check CloudTrail configuration
echo "CloudTrail Status:"
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,IsLogging]' \
    --output table

# Check Config service status
echo -e "\nAWS Config Status:"
aws configservice describe-configuration-recorders \
    --query 'ConfigurationRecorders[*].[name,recordingGroup.allSupported,recordingGroup.includeGlobalResourceTypes]' \
    --output table

# Check Security Hub status
echo -e "\nSecurity Hub Status:"
aws securityhub describe-hub \
    --query '[HubArn,SubscribedAt,AutoEnableControls]' \
    --output table 2>/dev/null || echo "Security Hub not enabled"

# Check GuardDuty status
echo -e "\nGuardDuty Status:"
aws guardduty list-detectors \
    --query 'DetectorIds[*]' --output text | \
while read detector_id; do
    if [ ! -z "$detector_id" ]; then
        aws guardduty get-detector --detector-id $detector_id \
            --query '[Status,ServiceRole,FindingPublishingFrequency]' \
            --output table
    else
        echo "GuardDuty not enabled"
    fi
done

# Check Inspector status
echo -e "\nInspector Status:"
aws inspector2 batch-get-account-status \
    --account-ids $(aws sts get-caller-identity --query Account --output text) \
    --query 'accounts[*].[accountId,status,resourceState]' \
    --output table 2>/dev/null || echo "Inspector not available or not enabled"

# Check Macie status
echo -e "\nMacie Status:"
aws macie2 get-macie-session \
    --query '[status,serviceRole,createdAt]' \
    --output table 2>/dev/null || echo "Macie not enabled"
```

**IAM Configuration Analysis:**
```bash
#!/bin/bash
# iam_configuration_analysis.sh

echo "=== IAM Configuration Analysis ==="

# Check for root account usage
echo "Root Account Access Keys:"
aws iam get-account-summary \
    --query 'SummaryMap.AccountAccessKeysPresent' \
    --output text

# Check MFA status for root account
echo -e "\nRoot Account MFA Status:"
aws iam get-account-summary \
    --query 'SummaryMap.AccountMFAEnabled' \
    --output text

# List users without MFA
echo -e "\nUsers without MFA:"
aws iam list-users --query 'Users[*].UserName' --output text | \
while read username; do
    mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].SerialNumber' --output text)
    if [ -z "$mfa_devices" ]; then
        echo "$username"
    fi
done

# Check for unused access keys
echo -e "\nAccess Key Usage Analysis:"
aws iam list-users --query 'Users[*].UserName' --output text | \
while read username; do
    aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[*].[UserName,AccessKeyId,Status,CreateDate]' --output table
done

# Check password policy
echo -e "\nPassword Policy:"
aws iam get-account-password-policy \
    --query 'PasswordPolicy.[MinimumPasswordLength,RequireSymbols,RequireNumbers,RequireUppercaseCharacters,RequireLowercaseCharacters,AllowUsersToChangePassword,MaxPasswordAge]' \
    --output table 2>/dev/null || echo "No password policy configured"

# List overly permissive policies
echo -e "\nPolicies with Administrative Access:"
aws iam list-policies --scope Local \
    --query 'Policies[*].[PolicyName,Arn]' --output text | \
while read policy_name policy_arn; do
    policy_doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id $(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text) --query 'PolicyVersion.Document' --output json)
    if echo "$policy_doc" | grep -q '"Effect": "Allow".*"Action": "\*".*"Resource": "\*"'; then
        echo "$policy_name has administrative permissions"
    fi
done
```

#### 2. Network Security Assessment

**VPC and Network Configuration Analysis:**
```bash
#!/bin/bash
# network_security_assessment.sh

echo "=== Network Security Assessment ==="

# Check VPC Flow Logs
echo "VPC Flow Logs Status:"
aws ec2 describe-flow-logs \
    --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogStatus,DeliverLogsStatus]' \
    --output table

# Check default security groups
echo -e "\nDefault Security Groups:"
aws ec2 describe-security-groups \
    --filters Name=group-name,Values=default \
    --query 'SecurityGroups[*].[GroupId,VpcId,IpPermissions[*].[IpProtocol,FromPort,ToPort,IpRanges[*].CidrIp]]' \
    --output table

# Check for overly permissive security groups
echo -e "\nSecurity Groups with 0.0.0.0/0 Access:"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,VpcId]' \
    --output table

# Check NACLs
echo -e "\nNetwork ACLs:"
aws ec2 describe-network-acls \
    --query 'NetworkAcls[*].[NetworkAclId,VpcId,IsDefault,Entries[?RuleAction==`allow`].[RuleNumber,Protocol,CidrBlock]]' \
    --output table

# Check Internet Gateways
echo -e "\nInternet Gateways:"
aws ec2 describe-internet-gateways \
    --query 'InternetGateways[*].[InternetGatewayId,State,Attachments[*].VpcId]' \
    --output table

# Check NAT Gateways
echo -e "\nNAT Gateways:"
aws ec2 describe-nat-gateways \
    --query 'NatGateways[*].[NatGatewayId,State,VpcId,SubnetId]' \
    --output table

# Check VPC Endpoints
echo -e "\nVPC Endpoints:"
aws ec2 describe-vpc-endpoints \
    --query 'VpcEndpoints[*].[VpcEndpointId,VpcId,ServiceName,State]' \
    --output table
```

#### 3. Data Protection Assessment

**Encryption and Data Security Analysis:**
```bash
#!/bin/bash
# data_protection_assessment.sh

echo "=== Data Protection Assessment ==="

# Check S3 bucket encryption
echo "S3 Bucket Encryption Status:"
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null)
    if [ "$encryption" = "None" ] || [ -z "$encryption" ]; then
        echo "$bucket: No encryption"
    else
        echo "$bucket: $encryption"
    fi
done

# Check S3 bucket public access
echo -e "\nS3 Bucket Public Access:"
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    public_access=$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text 2>/dev/null)
    if [ -z "$public_access" ] || echo "$public_access" | grep -q "False"; then
        echo "$bucket: May have public access"
    fi
done

# Check EBS encryption
echo -e "\nEBS Volume Encryption:"
aws ec2 describe-volumes \
    --query 'Volumes[*].[VolumeId,Encrypted,KmsKeyId,State]' \
    --output table

# Check RDS encryption
echo -e "\nRDS Instance Encryption:"
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]' \
    --output table

# Check KMS key usage
echo -e "\nKMS Keys:"
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
while read key_id; do
    key_info=$(aws kms describe-key --key-id "$key_id" --query '[KeyMetadata.KeyId,KeyMetadata.KeyUsage,KeyMetadata.KeyState,KeyMetadata.Description]' --output text)
    echo "$key_info"
done

# Check Secrets Manager secrets
echo -e "\nSecrets Manager Secrets:"
aws secretsmanager list-secrets \
    --query 'SecretList[*].[Name,KmsKeyId,LastChangedDate]' \
    --output table
```

### Risk Assessment and Gap Analysis

#### Security Risk Matrix

**High Risk Areas:**
```yaml
high_risk_findings:
  identity_access:
    - "Root account access keys present"
    - "Users without MFA enabled"
    - "Overly permissive IAM policies"
    - "Unused access keys not rotated"
    
  network_security:
    - "Security groups allowing 0.0.0.0/0 access"
    - "VPC Flow Logs not enabled"
    - "Default security groups with open rules"
    - "Missing VPC endpoints for AWS services"
    
  data_protection:
    - "Unencrypted S3 buckets"
    - "Unencrypted EBS volumes"
    - "S3 buckets with public access"
    - "Secrets stored in plain text"
    
  monitoring_detection:
    - "CloudTrail not enabled in all regions"
    - "GuardDuty not enabled"
    - "Security Hub not configured"
    - "No automated security alerting"
```

**Medium Risk Areas:**
```yaml
medium_risk_findings:
  compliance:
    - "AWS Config not enabled"
    - "Missing compliance monitoring"
    - "Incomplete audit logging"
    - "No regular access reviews"
    
  incident_response:
    - "No incident response plan"
    - "Untested security procedures"
    - "No automated response capabilities"
    - "Limited forensic capabilities"
    
  application_security:
    - "No secure development practices"
    - "Missing application security testing"
    - "Unpatched systems and applications"
    - "No dependency vulnerability scanning"
```

#### Compliance Requirements Assessment

**Regulatory Compliance Checklist:**
```bash
#!/bin/bash
# compliance_assessment.sh

echo "=== Compliance Requirements Assessment ==="

# Check for common compliance frameworks
cat > compliance_requirements.yaml << 'EOF'
compliance_frameworks:
  pci_dss:
    applicable: false
    requirements:
      - "Network segmentation and access controls"
      - "Strong access control measures"
      - "Regular monitoring and testing"
      - "Information security policy"
    
  hipaa:
    applicable: false
    requirements:
      - "Access control and user authentication"
      - "Audit controls and logging"
      - "Data integrity and encryption"
      - "Transmission security"
    
  sox:
    applicable: false
    requirements:
      - "Access controls and segregation of duties"
      - "Change management procedures"
      - "Monitoring and logging"
      - "Data retention and archival"
    
  gdpr:
    applicable: true
    requirements:
      - "Data protection by design and default"
      - "Data subject rights and consent"
      - "Data breach notification"
      - "Privacy impact assessments"
    
  iso_27001:
    applicable: false
    requirements:
      - "Information security management system"
      - "Risk assessment and treatment"
      - "Security controls implementation"
      - "Continuous improvement"

current_compliance_status:
  data_encryption: "Partial - some services encrypted"
  access_logging: "Enabled - CloudTrail configured"
  access_controls: "Needs improvement - overly permissive policies"
  incident_response: "Not implemented - no formal procedures"
  vulnerability_management: "Basic - manual patching only"
  security_monitoring: "Partial - basic monitoring enabled"
EOF

echo "Compliance assessment template created: compliance_requirements.yaml"
echo "Review and update based on your specific regulatory requirements"
```

## Review Planning

### Review Strategy Selection

#### 1. Comprehensive Security Review
**When to Use:**
- First-time Well-Architected security review
- Major security incidents or breaches
- Regulatory compliance requirements
- Significant architecture changes

**Timeline:** 6-8 weeks
**Resources:** Security team, compliance team, architecture team, business stakeholders

#### 2. Focused Security Assessment
**When to Use:**
- Specific security concerns or incidents
- Targeted compliance requirements
- Regular quarterly security reviews
- Pre-deployment security validation

**Timeline:** 3-4 weeks
**Resources:** Security team, technical team

#### 3. Rapid Security Audit
**When to Use:**
- Quick security posture assessment
- Vendor security evaluation
- Executive security briefing
- Incident response preparation

**Timeline:** 1-2 weeks
**Resources:** Senior security architect, lead engineer

### Review Team Assembly

#### Core Team Roles

**Security Review Lead (CISO/Security Architect):**
- Overall security strategy and governance
- Risk assessment and prioritization
- Compliance and regulatory requirements
- Stakeholder communication and reporting

**Identity and Access Management Specialist:**
- IAM policies and role configurations
- Authentication and authorization mechanisms
- Privilege management and access reviews
- Identity federation and SSO implementation

**Infrastructure Security Engineer:**
- Network security and segmentation
- Compute and storage security
- Security group and firewall configurations
- Infrastructure monitoring and protection

**Application Security Engineer:**
- Secure development practices
- Application security testing and validation
- Code security and vulnerability management
- Third-party component security assessment

#### Extended Team (As Needed)

**Compliance Officer:**
- Regulatory requirements and frameworks
- Audit preparation and documentation
- Policy development and enforcement
- Risk management and reporting

**Incident Response Coordinator:**
- Incident response planning and procedures
- Security event analysis and investigation
- Forensic capabilities and evidence handling
- Business continuity and disaster recovery

**Data Protection Officer:**
- Data classification and handling procedures
- Privacy requirements and regulations
- Data lifecycle management
- Encryption and key management

### Review Timeline Template

#### Week 1-2: Preparation and Current State Assessment
- [ ] **Day 1-2**: Team assembly and scope definition
- [ ] **Day 3-5**: Current security configuration inventory
- [ ] **Day 6-8**: Risk assessment and gap analysis
- [ ] **Day 9-10**: Compliance requirements review

#### Week 3-4: Well-Architected Tool Security Review
- [ ] **Day 1**: Access tool and define workload
- [ ] **Day 2-3**: Complete Security Foundations and IAM questions
- [ ] **Day 4-5**: Complete Detection and Infrastructure Protection questions
- [ ] **Day 6-7**: Complete Data Protection and Incident Response questions
- [ ] **Day 8**: Complete Application Security questions

#### Week 5-6: Deep Dive Analysis and Testing
- [ ] **Day 1-2**: Security testing and validation
- [ ] **Day 3-4**: Penetration testing or vulnerability assessment
- [ ] **Day 5-6**: Compliance mapping and gap analysis
- [ ] **Day 7**: Review results and prioritize findings

#### Week 7-8: Recommendations and Implementation Planning
- [ ] **Day 1-3**: Develop security improvement recommendations
- [ ] **Day 4-5**: Create implementation roadmap and timeline
- [ ] **Day 6-7**: Cost-benefit analysis and resource planning
- [ ] **Day 8**: Final review and stakeholder presentation

## Step-by-Step Review Process

### Phase 1: Access the AWS Well-Architected Tool

#### 1. Initial Setup and Workload Definition

**Access the Tool:**
1. Sign in to the AWS Management Console
2. Navigate to AWS Well-Architected Tool: https://console.aws.amazon.com/wellarchitected/
3. Review the security-focused introduction and features

**Define Your Workload:**
1. Click **Define workload** on the main page
2. Complete the workload definition form:

**Basic Information:**
- **Name**: "Production Customer Portal"
- **Description**: "Customer-facing web application handling sensitive customer data and financial transactions"
- **Review Owner**: "Chief Information Security Officer"
- **Environment**: Production
- **Regions**: Primary (us-east-1), Secondary (us-west-2)

**Security-Specific Configuration:**
- **Industry**: Select relevant industry for compliance considerations
- **Account IDs**: Include all AWS accounts in scope
- **Tags**: Add security and compliance-related tags

**Lens Selection:**
- Select **AWS Well-Architected Framework** lens
- Consider additional security-focused lenses (e.g., Financial Services Lens, Healthcare Lens)

### Phase 2: Security Foundations Review

#### SEC 1: How do you securely operate your workload?

**Key Focus Areas:**
- Security governance and organizational structure
- Security policies and procedures
- Security training and awareness
- Threat modeling and risk assessment

**Security Governance Assessment:**
```bash
#!/bin/bash
# security_governance_assessment.sh

echo "=== Security Governance Assessment ==="

# Check AWS Organizations setup
echo "AWS Organizations Structure:"
aws organizations describe-organization \
    --query '[Organization.Id,Organization.MasterAccountId,Organization.FeatureSet]' \
    --output table 2>/dev/null || echo "AWS Organizations not configured"

# Check Service Control Policies
echo -e "\nService Control Policies:"
aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
    --query 'Policies[*].[Name,Id,AwsManaged]' \
    --output table 2>/dev/null || echo "No SCPs configured"

# Check AWS Config compliance
echo -e "\nAWS Config Compliance Status:"
aws configservice get-compliance-summary-by-config-rule \
    --query '[ComplianceSummary.ComplianceByConfigRule.COMPLIANT,ComplianceSummary.ComplianceByConfigRule.NON_COMPLIANT]' \
    --output table

# Check Security Hub compliance standards
echo -e "\nSecurity Hub Compliance Standards:"
aws securityhub get-enabled-standards \
    --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' \
    --output table 2>/dev/null || echo "Security Hub not enabled"
```

**Best Practices Implementation:**

**Separate workloads using accounts:**
- Use AWS Organizations for multi-account strategy
- Implement account-level isolation for different environments
- Use Service Control Policies (SCPs) for governance
- Establish cross-account access patterns

**Secure account root user and properties:**
- Remove root account access keys
- Enable MFA for root account
- Use strong, unique password for root account
- Limit root account usage to essential tasks only

**Identify and validate control objectives:**
- Document security requirements and objectives
- Map controls to compliance frameworks
- Implement automated compliance checking
- Regular review and validation of controls

**Stay up to date with security threats and recommendations:**
- Subscribe to AWS security bulletins and advisories
- Implement threat intelligence feeds
- Regular security training and awareness programs
- Participate in security communities and forums

### Phase 3: Identity and Access Management Review

#### SEC 2: How do you manage identities for people and machines?

**Key Focus Areas:**
- Identity provider integration and federation
- User lifecycle management
- Machine identity and service accounts
- Multi-factor authentication implementation

**Identity Management Assessment:**
```bash
#!/bin/bash
# identity_management_assessment.sh

echo "=== Identity Management Assessment ==="

# Check IAM Identity Center (SSO) configuration
echo "IAM Identity Center Status:"
aws sso-admin list-instances \
    --query 'Instances[*].[InstanceArn,Status,CreatedDate]' \
    --output table 2>/dev/null || echo "IAM Identity Center not configured"

# Check SAML identity providers
echo -e "\nSAML Identity Providers:"
aws iam list-saml-providers \
    --query 'SAMLProviderList[*].[Arn,CreateDate]' \
    --output table

# Check OIDC identity providers
echo -e "\nOIDC Identity Providers:"
aws iam list-open-id-connect-providers \
    --query 'OpenIDConnectProviderList[*].[Arn,CreateDate]' \
    --output table

# Check service-linked roles
echo -e "\nService-Linked Roles:"
aws iam list-roles \
    --query 'Roles[?contains(RoleName, `AWSServiceRole`)][RoleName,CreateDate]' \
    --output table

# Check cross-account roles
echo -e "\nCross-Account Roles:"
aws iam list-roles \
    --query 'Roles[?contains(AssumeRolePolicyDocument, `arn:aws:iam::`)][RoleName,CreateDate]' \
    --output table
```

**Best Practices Implementation:**

**Use strong sign-in mechanisms:**
- Implement multi-factor authentication (MFA) for all users
- Use hardware-based MFA devices for privileged accounts
- Enforce strong password policies
- Implement account lockout policies

**Use temporary credentials:**
- Use IAM roles instead of long-term access keys
- Implement AWS STS for temporary credentials
- Use service roles for applications and services
- Regularly rotate any long-term credentials

**Store and use secrets securely:**
- Use AWS Secrets Manager for application secrets
- Use AWS Systems Manager Parameter Store for configuration
- Implement automatic secret rotation
- Avoid hardcoding secrets in code or configuration

#### SEC 3: How do you manage permissions for people and machines?

**Key Focus Areas:**
- Least privilege access implementation
- Permission boundaries and guardrails
- Regular access reviews and auditing
- Automated permission management

**Permission Management Assessment:**
```bash
#!/bin/bash
# permission_management_assessment.sh

echo "=== Permission Management Assessment ==="

# Check for overly broad policies
echo "Policies with Administrative Access:"
aws iam list-policies --scope Local \
    --query 'Policies[*].[PolicyName,Arn]' --output text | \
while read policy_name policy_arn; do
    policy_doc=$(aws iam get-policy-version \
        --policy-arn "$policy_arn" \
        --version-id $(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text) \
        --query 'PolicyVersion.Document' --output json)
    if echo "$policy_doc" | jq -r '.Statement[]' | grep -q '"Effect": "Allow".*"Action": "\*".*"Resource": "\*"'; then
        echo "$policy_name"
    fi
done

# Check permission boundaries
echo -e "\nPermission Boundaries:"
aws iam list-users \
    --query 'Users[?PermissionsBoundary!=null].[UserName,PermissionsBoundary.PermissionsBoundaryArn]' \
    --output table

# Check unused roles and policies
echo -e "\nRole Usage Analysis:"
aws iam generate-service-last-accessed-details \
    --arn $(aws sts get-caller-identity --query Arn --output text) \
    --granularity SERVICE_LEVEL

# Check for inline policies
echo -e "\nInline Policies:"
aws iam list-users --query 'Users[*].UserName' --output text | \
while read username; do
    inline_policies=$(aws iam list-user-policies --user-name "$username" --query 'PolicyNames[*]' --output text)
    if [ ! -z "$inline_policies" ]; then
        echo "User $username has inline policies: $inline_policies"
    fi
done
```

**Best Practices Implementation:**

**Define permission guardrails for your organization:**
- Implement Service Control Policies (SCPs) in AWS Organizations
- Use permission boundaries for delegated administration
- Establish baseline security policies for all accounts
- Implement automated policy validation

**Grant least privilege access:**
- Start with minimal permissions and add as needed
- Use AWS managed policies where appropriate
- Implement just-in-time access for privileged operations
- Regular review and removal of unused permissions

**Reduce permissions continuously:**
- Use AWS Access Analyzer to identify unused permissions
- Implement automated access reviews
- Monitor and alert on privilege escalation
- Use AWS CloudTrail to analyze actual permission usage

**Establish emergency access process:**
- Create break-glass procedures for emergency access
- Implement emergency access roles with time-limited access
- Log and monitor all emergency access usage
- Regular testing of emergency access procedures
### Phase 4: Detection Review

#### SEC 4: How do you detect and investigate security events?

**Key Focus Areas:**
- Comprehensive logging and monitoring
- Threat detection and analysis
- Security event correlation and alerting
- Forensic capabilities and investigation tools

**Detection Capabilities Assessment:**
```bash
#!/bin/bash
# detection_capabilities_assessment.sh

echo "=== Detection Capabilities Assessment ==="

# Check CloudTrail configuration
echo "CloudTrail Configuration:"
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,S3BucketName,IncludeGlobalServiceEvents,IsMultiRegionTrail,LogFileValidationEnabled]' \
    --output table

# Check CloudWatch Log Groups
echo -e "\nCloudWatch Log Groups:"
aws logs describe-log-groups \
    --query 'logGroups[*].[logGroupName,retentionInDays,storedBytes]' \
    --output table

# Check GuardDuty findings
echo -e "\nGuardDuty Findings Summary:"
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
while read detector_id; do
    if [ ! -z "$detector_id" ]; then
        aws guardduty get-findings-statistics \
            --detector-id "$detector_id" \
            --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}' \
            --finding-statistic-types COUNT_BY_SEVERITY \
            --query 'FindingStatistics.CountBySeverity' \
            --output table
    fi
done

# Check Security Hub findings
echo -e "\nSecurity Hub Findings Summary:"
aws securityhub get-findings \
    --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}]}' \
    --query 'Findings[*].[Id,Title,Severity.Label,ProductArn]' \
    --output table --max-items 10 2>/dev/null || echo "Security Hub not enabled"

# Check Config compliance
echo -e "\nConfig Rules Compliance:"
aws configservice get-compliance-summary-by-config-rule \
    --query 'ComplianceSummary' \
    --output table

# Check VPC Flow Logs
echo -e "\nVPC Flow Logs:"
aws ec2 describe-flow-logs \
    --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestination,LogStatus]' \
    --output table
```

**Best Practices Implementation:**

**Configure service and application logging:**
- Enable CloudTrail in all regions and accounts
- Configure VPC Flow Logs for network monitoring
- Enable application-level logging for custom applications
- Use structured logging formats for better analysis

**Analyze logs, findings, and metrics centrally:**
- Use Amazon CloudWatch for centralized log aggregation
- Implement AWS Security Hub for security findings correlation
- Use Amazon OpenSearch for log analysis and visualization
- Create custom dashboards for security metrics

**Automate response to events:**
- Use Amazon EventBridge for event-driven automation
- Implement AWS Lambda functions for automated remediation
- Use AWS Systems Manager for automated response actions
- Create custom automation workflows for common scenarios

### Phase 5: Infrastructure Protection Review

#### SEC 5: How do you protect your network resources?

**Key Focus Areas:**
- Network segmentation and isolation
- Traffic filtering and access controls
- DDoS protection and edge security
- Private connectivity and VPC design

**Network Protection Assessment:**
```bash
#!/bin/bash
# network_protection_assessment.sh

echo "=== Network Protection Assessment ==="

# Check VPC configuration
echo "VPC Configuration:"
aws ec2 describe-vpcs \
    --query 'Vpcs[*].[VpcId,CidrBlock,State,IsDefault]' \
    --output table

# Check subnet configuration
echo -e "\nSubnet Configuration:"
aws ec2 describe-subnets \
    --query 'Subnets[*].[SubnetId,VpcId,CidrBlock,AvailabilityZone,MapPublicIpOnLaunch]' \
    --output table

# Check security groups with broad access
echo -e "\nSecurity Groups with Broad Access:"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`22` || FromPort==`3389` || FromPort==`80` || FromPort==`443`)]].[GroupId,GroupName,Description]' \
    --output table

# Check WAF configuration
echo -e "\nWAF Web ACLs:"
aws wafv2 list-web-acls --scope CLOUDFRONT \
    --query 'WebACLs[*].[Name,Id,Description]' \
    --output table 2>/dev/null || echo "WAF not configured"

# Check Shield Advanced status
echo -e "\nShield Advanced Status:"
aws shield describe-subscription \
    --query '[Subscription.SubscriptionLimits,Subscription.TimeCommitmentInSeconds]' \
    --output table 2>/dev/null || echo "Shield Advanced not enabled"

# Check Network Load Balancers
echo -e "\nNetwork Load Balancers:"
aws elbv2 describe-load-balancers \
    --query 'LoadBalancers[?Type==`network`].[LoadBalancerName,Scheme,State.Code]' \
    --output table

# Check VPC Endpoints
echo -e "\nVPC Endpoints:"
aws ec2 describe-vpc-endpoints \
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,VpcId,State]' \
    --output table
```

**Best Practices Implementation:**

**Create network layers:**
- Implement multi-tier VPC architecture with public, private, and data subnets
- Use separate subnets for different application tiers
- Implement network segmentation based on security requirements
- Use multiple Availability Zones for high availability

**Control traffic at all layers:**
- Configure security groups with least privilege access
- Use Network ACLs for subnet-level filtering
- Implement AWS WAF for application-layer protection
- Use AWS Shield for DDoS protection

**Automate network protection:**
- Use AWS Config rules for network compliance monitoring
- Implement automated security group management
- Use AWS Systems Manager for network configuration management
- Create automated responses to network security events

#### SEC 6: How do you protect your compute resources?

**Key Focus Areas:**
- Instance and container security
- Patch management and vulnerability scanning
- Runtime protection and monitoring
- Secure configuration management

**Compute Protection Assessment:**
```bash
#!/bin/bash
# compute_protection_assessment.sh

echo "=== Compute Protection Assessment ==="

# Check EC2 instance security
echo "EC2 Instance Security Configuration:"
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].[InstanceId,ImageId,InstanceType,State.Name,SecurityGroups[*].GroupId]' \
    --output table

# Check Systems Manager patch compliance
echo -e "\nPatch Compliance Status:"
aws ssm describe-instance-patch-states \
    --query 'InstancePatchStates[*].[InstanceId,PatchGroup,InstalledCount,InstalledOtherCount,MissingCount,FailedCount]' \
    --output table

# Check Inspector findings
echo -e "\nInspector Findings:"
aws inspector2 list-findings \
    --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
    --query 'findings[*].[findingArn,severity,title,type]' \
    --output table --max-items 10 2>/dev/null || echo "Inspector not enabled"

# Check ECS cluster security
echo -e "\nECS Cluster Configuration:"
aws ecs list-clusters --query 'clusterArns[*]' --output text | \
while read cluster_arn; do
    aws ecs describe-clusters --clusters "$cluster_arn" \
        --query 'clusters[*].[clusterName,status,runningTasksCount,pendingTasksCount]' \
        --output table
done

# Check Lambda function security
echo -e "\nLambda Function Security:"
aws lambda list-functions \
    --query 'Functions[*].[FunctionName,Runtime,Role,VpcConfig.VpcId]' \
    --output table

# Check container image scanning
echo -e "\nECR Image Scan Results:"
aws ecr describe-repositories --query 'repositories[*].repositoryName' --output text | \
while read repo_name; do
    scan_results=$(aws ecr describe-image-scan-findings --repository-name "$repo_name" --image-id imageTag=latest --query 'imageScanFindings.findingCounts' --output json 2>/dev/null)
    if [ ! -z "$scan_results" ]; then
        echo "$repo_name: $scan_results"
    fi
done
```

**Best Practices Implementation:**

**Perform vulnerability management:**
- Enable Amazon Inspector for vulnerability assessment
- Implement automated patch management with Systems Manager
- Use container image scanning in Amazon ECR
- Regular security assessments and penetration testing

**Reduce attack surface:**
- Use minimal base images for containers
- Remove unnecessary software and services
- Implement least privilege for service accounts
- Use AWS Systems Manager Session Manager instead of SSH

**Implement managed services:**
- Use AWS managed services to reduce operational overhead
- Leverage AWS Fargate for serverless containers
- Use AWS Lambda for serverless compute
- Implement AWS managed databases and caching services

### Phase 6: Data Protection Review

#### SEC 7: How do you classify your data?

**Key Focus Areas:**
- Data classification schemes and policies
- Data discovery and inventory
- Automated data classification tools
- Data handling procedures based on classification

**Data Classification Assessment:**
```bash
#!/bin/bash
# data_classification_assessment.sh

echo "=== Data Classification Assessment ==="

# Check S3 bucket inventory and classification
echo "S3 Bucket Data Classification:"
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    # Check for classification tags
    tags=$(aws s3api get-bucket-tagging --bucket "$bucket" --query 'TagSet[?Key==`DataClassification`].Value' --output text 2>/dev/null)
    if [ -z "$tags" ]; then
        echo "$bucket: No classification tag"
    else
        echo "$bucket: $tags"
    fi
done

# Check Macie data classification results
echo -e "\nMacie Data Classification Results:"
aws macie2 get-classification-job \
    --job-id $(aws macie2 list-classification-jobs --query 'items[0].jobId' --output text) \
    --query '[name,jobStatus,statistics]' \
    --output table 2>/dev/null || echo "Macie not configured"

# Check RDS database classification
echo -e "\nRDS Database Classification:"
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,Engine,DBInstanceClass,StorageEncrypted]' \
    --output table

# Check DynamoDB table classification
echo -e "\nDynamoDB Table Classification:"
aws dynamodb list-tables --query 'TableNames[*]' --output text | \
while read table_name; do
    tags=$(aws dynamodb list-tags-of-resource --resource-arn "arn:aws:dynamodb:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):table/$table_name" --query 'Tags[?Key==`DataClassification`].Value' --output text 2>/dev/null)
    if [ -z "$tags" ]; then
        echo "$table_name: No classification tag"
    else
        echo "$table_name: $tags"
    fi
done

# Check for sensitive data patterns
echo -e "\nSensitive Data Pattern Analysis:"
cat > data_classification_template.yaml << 'EOF'
data_classification_levels:
  public:
    description: "Information that can be freely shared"
    examples: ["Marketing materials", "Public documentation"]
    handling: "No special protection required"
    
  internal:
    description: "Information for internal use only"
    examples: ["Internal procedures", "Employee directories"]
    handling: "Access controls and basic encryption"
    
  confidential:
    description: "Sensitive business information"
    examples: ["Financial data", "Customer information"]
    handling: "Strong access controls, encryption, audit logging"
    
  restricted:
    description: "Highly sensitive information"
    examples: ["PII", "Payment card data", "Health records"]
    handling: "Strict access controls, encryption, comprehensive monitoring"

data_discovery_tools:
  amazon_macie:
    enabled: false
    purpose: "Automated discovery of sensitive data in S3"
    
  aws_glue_datacatalog:
    enabled: false
    purpose: "Data discovery and cataloging"
    
  custom_classification:
    enabled: false
    purpose: "Custom data classification rules"
EOF

echo "Data classification template created: data_classification_template.yaml"
```

**Best Practices Implementation:**

**Identify the data within your workload:**
- Implement comprehensive data discovery processes
- Use Amazon Macie for automated sensitive data discovery
- Create data inventory and mapping documentation
- Regular data discovery scans and updates

**Define data protection controls:**
- Establish data classification schemes and policies
- Implement data handling procedures for each classification level
- Define retention and disposal policies
- Create data access and sharing guidelines

**Automate identification and classification:**
- Use AWS services for automated data classification
- Implement custom classification rules and patterns
- Use machine learning for intelligent data classification
- Regular validation and updating of classification rules

#### SEC 8: How do you protect your data at rest?

**Key Focus Areas:**
- Encryption implementation and key management
- Access controls and data isolation
- Backup and recovery procedures
- Data lifecycle management

**Data at Rest Protection Assessment:**
```bash
#!/bin/bash
# data_at_rest_assessment.sh

echo "=== Data at Rest Protection Assessment ==="

# Check S3 encryption configuration
echo "S3 Bucket Encryption Status:"
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault' --output json 2>/dev/null)
    if [ -z "$encryption" ]; then
        echo "$bucket: No encryption configured"
    else
        sse_algorithm=$(echo "$encryption" | jq -r '.SSEAlgorithm')
        kms_key=$(echo "$encryption" | jq -r '.KMSMasterKeyID // "Default"')
        echo "$bucket: $sse_algorithm with key $kms_key"
    fi
done

# Check EBS volume encryption
echo -e "\nEBS Volume Encryption Status:"
aws ec2 describe-volumes \
    --query 'Volumes[*].[VolumeId,Encrypted,KmsKeyId,Size,State]' \
    --output table

# Check RDS encryption
echo -e "\nRDS Instance Encryption Status:"
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId,Engine]' \
    --output table

# Check DynamoDB encryption
echo -e "\nDynamoDB Table Encryption:"
aws dynamodb list-tables --query 'TableNames[*]' --output text | \
while read table_name; do
    encryption=$(aws dynamodb describe-table --table-name "$table_name" --query 'Table.SSEDescription.Status' --output text 2>/dev/null)
    if [ "$encryption" = "ENABLED" ]; then
        kms_key=$(aws dynamodb describe-table --table-name "$table_name" --query 'Table.SSEDescription.KMSMasterKeyArn' --output text)
        echo "$table_name: Encrypted with $kms_key"
    else
        echo "$table_name: Not encrypted"
    fi
done

# Check KMS key policies and usage
echo -e "\nKMS Key Configuration:"
aws kms list-keys --query 'Keys[*].KeyId' --output text | \
while read key_id; do
    key_info=$(aws kms describe-key --key-id "$key_id" --query '[KeyMetadata.KeyId,KeyMetadata.KeyUsage,KeyMetadata.KeyState,KeyMetadata.Description]' --output text)
    echo "$key_info"
done

# Check EFS encryption
echo -e "\nEFS File System Encryption:"
aws efs describe-file-systems \
    --query 'FileSystems[*].[FileSystemId,Encrypted,KmsKeyId,LifeCycleState]' \
    --output table

# Check Redshift encryption
echo -e "\nRedshift Cluster Encryption:"
aws redshift describe-clusters \
    --query 'Clusters[*].[ClusterIdentifier,Encrypted,KmsKeyId,ClusterStatus]' \
    --output table 2>/dev/null || echo "No Redshift clusters found"
```

**Best Practices Implementation:**

**Implement secure key management:**
- Use AWS KMS for centralized key management
- Implement key rotation policies
- Use customer-managed keys for sensitive data
- Implement proper key access controls and policies

**Enforce encryption at rest:**
- Enable encryption for all data storage services
- Use strong encryption algorithms (AES-256)
- Implement encryption for databases, file systems, and object storage
- Regular validation of encryption configurations

**Automate data at rest protection:**
- Use AWS Config rules to enforce encryption requirements
- Implement automated encryption for new resources
- Use AWS CloudFormation for consistent encryption deployment
- Monitor and alert on unencrypted resources

#### SEC 9: How do you protect your data in transit?

**Key Focus Areas:**
- Transport encryption implementation
- Certificate management and PKI
- API security and authentication
- Network-level encryption

**Data in Transit Protection Assessment:**
```bash
#!/bin/bash
# data_in_transit_assessment.sh

echo "=== Data in Transit Protection Assessment ==="

# Check SSL/TLS certificate configuration
echo "SSL/TLS Certificates (ACM):"
aws acm list-certificates \
    --query 'CertificateSummaryList[*].[CertificateArn,DomainName,Status]' \
    --output table

# Check CloudFront SSL configuration
echo -e "\nCloudFront SSL Configuration:"
aws cloudfront list-distributions \
    --query 'DistributionList.Items[*].[Id,DomainName,ViewerCertificate.CertificateSource,ViewerCertificate.MinimumProtocolVersion]' \
    --output table

# Check Application Load Balancer SSL configuration
echo -e "\nApplication Load Balancer SSL Configuration:"
aws elbv2 describe-load-balancers \
    --query 'LoadBalancers[?Type==`application`].[LoadBalancerName,Scheme]' \
    --output text | \
while read lb_name scheme; do
    lb_arn=$(aws elbv2 describe-load-balancers --names "$lb_name" --query 'LoadBalancers[0].LoadBalancerArn' --output text)
    listeners=$(aws elbv2 describe-listeners --load-balancer-arn "$lb_arn" --query 'Listeners[*].[Protocol,Port,SslPolicy]' --output table)
    echo "Load Balancer: $lb_name"
    echo "$listeners"
done

# Check API Gateway SSL configuration
echo -e "\nAPI Gateway SSL Configuration:"
aws apigateway get-rest-apis \
    --query 'items[*].[id,name,createdDate]' \
    --output table

# Check RDS SSL configuration
echo -e "\nRDS SSL Configuration:"
aws rds describe-db-instances \
    --query 'DBInstances[*].[DBInstanceIdentifier,Engine,CACertificateIdentifier]' \
    --output table

# Check ElastiCache encryption in transit
echo -e "\nElastiCache Encryption in Transit:"
aws elasticache describe-cache-clusters \
    --query 'CacheClusters[*].[CacheClusterId,TransitEncryptionEnabled,AtRestEncryptionEnabled]' \
    --output table 2>/dev/null || echo "No ElastiCache clusters found"

# Check VPC endpoints for private connectivity
echo -e "\nVPC Endpoints for Private Connectivity:"
aws ec2 describe-vpc-endpoints \
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State,VpcId]' \
    --output table
```

**Best Practices Implementation:**

**Implement secure key and certificate management:**
- Use AWS Certificate Manager for SSL/TLS certificates
- Implement automatic certificate renewal
- Use strong cipher suites and protocols
- Regular certificate inventory and validation

**Enforce encryption in transit:**
- Use HTTPS/TLS for all web traffic
- Implement SSL/TLS for database connections
- Use VPC endpoints for private AWS service connectivity
- Encrypt inter-service communication

**Automate detection of unintended data access:**
- Monitor for unencrypted connections
- Use AWS Config rules to enforce encryption in transit
- Implement network monitoring and analysis
- Alert on policy violations and security events

### Phase 7: Incident Response Review

#### SEC 10: How do you anticipate, respond to, and recover from incidents?

**Key Focus Areas:**
- Incident response planning and preparation
- Detection and analysis capabilities
- Containment and eradication procedures
- Recovery and post-incident activities

**Incident Response Readiness Assessment:**
```bash
#!/bin/bash
# incident_response_assessment.sh

echo "=== Incident Response Readiness Assessment ==="

# Check CloudTrail for incident investigation capabilities
echo "CloudTrail Configuration for Incident Response:"
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,LogFileValidationEnabled,EventSelectors[0].ReadWriteType,EventSelectors[0].IncludeManagementEvents]' \
    --output table

# Check AWS Config for configuration history
echo -e "\nAWS Config Configuration History:"
aws configservice describe-configuration-recorders \
    --query 'ConfigurationRecorders[*].[name,recordingGroup.allSupported,recordingGroup.includeGlobalResourceTypes]' \
    --output table

# Check Security Hub for centralized findings
echo -e "\nSecurity Hub Integration Status:"
aws securityhub describe-hub \
    --query '[HubArn,AutoEnableControls,SubscribedAt]' \
    --output table 2>/dev/null || echo "Security Hub not enabled"

# Check GuardDuty for threat detection
echo -e "\nGuardDuty Threat Detection:"
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
while read detector_id; do
    if [ ! -z "$detector_id" ]; then
        aws guardduty get-detector --detector-id "$detector_id" \
            --query '[Status,ServiceRole,FindingPublishingFrequency]' \
            --output table
    fi
done

# Check Systems Manager for incident response automation
echo -e "\nSystems Manager Automation Documents:"
aws ssm list-documents \
    --filters Key=DocumentType,Values=Automation \
    --query 'DocumentIdentifiers[?contains(Name, `incident`) || contains(Name, `response`) || contains(Name, `remediat`)][Name,DocumentType,CreatedDate]' \
    --output table

# Check Lambda functions for automated response
echo -e "\nLambda Functions for Incident Response:"
aws lambda list-functions \
    --query 'Functions[?contains(FunctionName, `incident`) || contains(FunctionName, `response`) || contains(FunctionName, `security`)][FunctionName,Runtime,LastModified]' \
    --output table

# Check SNS topics for incident notification
echo -e "\nSNS Topics for Incident Notification:"
aws sns list-topics \
    --query 'Topics[*].TopicArn' --output text | \
while read topic_arn; do
    topic_name=$(echo "$topic_arn" | cut -d':' -f6)
    if echo "$topic_name" | grep -qi "security\|incident\|alert"; then
        echo "$topic_arn"
    fi
done
```

**Best Practices Implementation:**

**Prepare:**
- Develop comprehensive incident response plans and procedures
- Create incident response team with defined roles and responsibilities
- Implement incident response tools and automation
- Regular training and tabletop exercises

**Simulate:**
- Conduct regular incident response simulations and drills
- Test incident response procedures and tools
- Validate communication and escalation procedures
- Document lessons learned and improve procedures

**Iterate:**
- Regular review and update of incident response procedures
- Incorporate new threats and attack vectors
- Update tools and automation based on lessons learned
- Continuous improvement of incident response capabilities

### Phase 8: Application Security Review

#### SEC 11: How do you incorporate and validate the security properties of applications?

**Key Focus Areas:**
- Secure development lifecycle implementation
- Security testing and validation
- Dependency management and vulnerability scanning
- Code security and static analysis

**Application Security Assessment:**
```bash
#!/bin/bash
# application_security_assessment.sh

echo "=== Application Security Assessment ==="

# Check CodeBuild projects for security scanning
echo "CodeBuild Security Scanning Configuration:"
aws codebuild list-projects --query 'projects[*]' --output text | \
while read project_name; do
    project_info=$(aws codebuild batch-get-projects --names "$project_name" --query 'projects[0].[name,source.type,artifacts.type]' --output text)
    echo "$project_info"
done

# Check CodePipeline for security gates
echo -e "\nCodePipeline Security Integration:"
aws codepipeline list-pipelines \
    --query 'pipelines[*].[name,created,updated]' \
    --output table

# Check ECR for container image scanning
echo -e "\nECR Image Scanning Configuration:"
aws ecr describe-repositories \
    --query 'repositories[*].[repositoryName,imageScanningConfiguration.scanOnPush]' \
    --output table

# Check Lambda function security configuration
echo -e "\nLambda Function Security Configuration:"
aws lambda list-functions \
    --query 'Functions[*].[FunctionName,Runtime,Role,Environment.Variables]' \
    --output table

# Check API Gateway security configuration
echo -e "\nAPI Gateway Security Configuration:"
aws apigateway get-rest-apis \
    --query 'items[*].[id,name,policy]' \
    --output table

# Check WAF rules for application protection
echo -e "\nWAF Rules Configuration:"
aws wafv2 list-web-acls --scope REGIONAL \
    --query 'WebACLs[*].[Name,Id,Description]' \
    --output table 2>/dev/null || echo "WAF not configured"
```

**Best Practices Implementation:**

**Train for application security:**
- Implement secure coding training for development teams
- Regular security awareness training and updates
- Establish security champions program
- Create secure coding guidelines and standards

**Automate testing throughout the development and release lifecycle:**
- Integrate security testing into CI/CD pipelines
- Implement static application security testing (SAST)
- Use dynamic application security testing (DAST)
- Implement dependency vulnerability scanning

**Perform regular penetration testing:**
- Schedule regular penetration testing by qualified professionals
- Implement automated vulnerability scanning
- Test both infrastructure and application layers
- Document and remediate identified vulnerabilities

**Manual code reviews:**
- Implement mandatory code review processes
- Focus on security-critical code sections
- Use security-focused code review checklists
- Document and track security-related code issues
## Testing and Validation

### Security Testing Framework

#### 1. Automated Security Testing

**Comprehensive Security Testing Script:**
```bash
#!/bin/bash
# comprehensive_security_testing.sh

echo "=== Comprehensive Security Testing ==="

# Function to test IAM configuration
test_iam_security() {
    echo "Testing IAM Security Configuration..."
    
    # Check for root account access keys
    root_keys=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)
    if [ "$root_keys" = "1" ]; then
        echo "❌ FAIL: Root account has access keys"
    else
        echo "✅ PASS: No root account access keys"
    fi
    
    # Check for users without MFA
    echo "Checking MFA status for all users..."
    aws iam list-users --query 'Users[*].UserName' --output text | \
    while read username; do
        mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].SerialNumber' --output text)
        if [ -z "$mfa_devices" ]; then
            echo "❌ FAIL: User $username has no MFA device"
        else
            echo "✅ PASS: User $username has MFA enabled"
        fi
    done
    
    # Check password policy
    password_policy=$(aws iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text 2>/dev/null)
    if [ -z "$password_policy" ] || [ "$password_policy" -lt 8 ]; then
        echo "❌ FAIL: Weak or missing password policy"
    else
        echo "✅ PASS: Password policy configured"
    fi
}

# Function to test network security
test_network_security() {
    echo "Testing Network Security Configuration..."
    
    # Check for overly permissive security groups
    permissive_sgs=$(aws ec2 describe-security-groups \
        --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`22` || FromPort==`3389`)]].[GroupId]' \
        --output text)
    
    if [ ! -z "$permissive_sgs" ]; then
        echo "❌ FAIL: Security groups allow SSH/RDP from 0.0.0.0/0: $permissive_sgs"
    else
        echo "✅ PASS: No overly permissive SSH/RDP access"
    fi
    
    # Check VPC Flow Logs
    flow_logs=$(aws ec2 describe-flow-logs --query 'FlowLogs[?LogStatus==`ACTIVE`]' --output text)
    if [ -z "$flow_logs" ]; then
        echo "❌ FAIL: VPC Flow Logs not enabled"
    else
        echo "✅ PASS: VPC Flow Logs enabled"
    fi
    
    # Check for default VPCs
    default_vpcs=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[*].VpcId' --output text)
    if [ ! -z "$default_vpcs" ]; then
        echo "⚠️  WARNING: Default VPC exists: $default_vpcs"
    else
        echo "✅ PASS: No default VPCs found"
    fi
}

# Function to test encryption
test_encryption() {
    echo "Testing Encryption Configuration..."
    
    # Check S3 bucket encryption
    echo "Checking S3 bucket encryption..."
    aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
    while read bucket; do
        encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null)
        if [ -z "$encryption" ] || [ "$encryption" = "None" ]; then
            echo "❌ FAIL: Bucket $bucket is not encrypted"
        else
            echo "✅ PASS: Bucket $bucket encrypted with $encryption"
        fi
    done
    
    # Check EBS volume encryption
    unencrypted_volumes=$(aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId]' --output text)
    if [ ! -z "$unencrypted_volumes" ]; then
        echo "❌ FAIL: Unencrypted EBS volumes found: $unencrypted_volumes"
    else
        echo "✅ PASS: All EBS volumes encrypted"
    fi
    
    # Check RDS encryption
    unencrypted_rds=$(aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier]' --output text)
    if [ ! -z "$unencrypted_rds" ]; then
        echo "❌ FAIL: Unencrypted RDS instances found: $unencrypted_rds"
    else
        echo "✅ PASS: All RDS instances encrypted"
    fi
}

# Function to test logging and monitoring
test_logging_monitoring() {
    echo "Testing Logging and Monitoring Configuration..."
    
    # Check CloudTrail
    cloudtrail_status=$(aws cloudtrail describe-trails --query 'trailList[?IsLogging==`true`]' --output text)
    if [ -z "$cloudtrail_status" ]; then
        echo "❌ FAIL: CloudTrail not enabled or not logging"
    else
        echo "✅ PASS: CloudTrail enabled and logging"
    fi
    
    # Check GuardDuty
    guardduty_detectors=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
    if [ -z "$guardduty_detectors" ] || [ "$guardduty_detectors" = "None" ]; then
        echo "❌ FAIL: GuardDuty not enabled"
    else
        detector_status=$(aws guardduty get-detector --detector-id "$guardduty_detectors" --query 'Status' --output text)
        if [ "$detector_status" = "ENABLED" ]; then
            echo "✅ PASS: GuardDuty enabled and active"
        else
            echo "❌ FAIL: GuardDuty not active"
        fi
    fi
    
    # Check Config
    config_recorders=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text 2>/dev/null)
    if [ -z "$config_recorders" ] || [ "$config_recorders" = "None" ]; then
        echo "❌ FAIL: AWS Config not enabled"
    else
        echo "✅ PASS: AWS Config enabled"
    fi
}

# Run all security tests
echo "Starting comprehensive security testing..."
test_iam_security
echo ""
test_network_security
echo ""
test_encryption
echo ""
test_logging_monitoring
echo ""
echo "Security testing completed."
```

#### 2. Penetration Testing and Vulnerability Assessment

**Automated Vulnerability Scanning:**
```bash
#!/bin/bash
# vulnerability_scanning.sh

echo "=== Automated Vulnerability Scanning ==="

# Function to scan for common security misconfigurations
scan_security_misconfigurations() {
    echo "Scanning for Security Misconfigurations..."
    
    # Check for public S3 buckets
    echo "Checking for public S3 buckets..."
    aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
    while read bucket; do
        # Check bucket ACL
        public_acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text 2>/dev/null)
        if [ ! -z "$public_acl" ]; then
            echo "⚠️  WARNING: Bucket $bucket has public ACL"
        fi
        
        # Check bucket policy
        bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null)
        if echo "$bucket_policy" | grep -q '"Principal": "*"'; then
            echo "⚠️  WARNING: Bucket $bucket has public policy"
        fi
    done
    
    # Check for unused security groups
    echo "Checking for unused security groups..."
    aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName]' --output text | \
    while read group_id group_name; do
        # Check if security group is attached to any instances
        instances=$(aws ec2 describe-instances --filters "Name=instance.group-id,Values=$group_id" --query 'Reservations[*].Instances[*].InstanceId' --output text)
        # Check if security group is attached to any load balancers
        elbs=$(aws elbv2 describe-load-balancers --query "LoadBalancers[?contains(SecurityGroups, '$group_id')].LoadBalancerName" --output text)
        
        if [ -z "$instances" ] && [ -z "$elbs" ] && [ "$group_name" != "default" ]; then
            echo "⚠️  WARNING: Unused security group: $group_id ($group_name)"
        fi
    done
    
    # Check for overly broad IAM policies
    echo "Checking for overly broad IAM policies..."
    aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output text | \
    while read policy_name policy_arn; do
        policy_doc=$(aws iam get-policy-version \
            --policy-arn "$policy_arn" \
            --version-id $(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text) \
            --query 'PolicyVersion.Document' --output json)
        
        if echo "$policy_doc" | jq -r '.Statement[]' | grep -q '"Effect": "Allow".*"Action": "\*".*"Resource": "\*"'; then
            echo "⚠️  WARNING: Policy $policy_name has administrative permissions"
        fi
    done
}

# Function to check SSL/TLS configuration
check_ssl_tls_configuration() {
    echo "Checking SSL/TLS Configuration..."
    
    # Check CloudFront distributions
    aws cloudfront list-distributions --query 'DistributionList.Items[*].[Id,DomainName]' --output text | \
    while read dist_id domain_name; do
        viewer_protocol=$(aws cloudfront get-distribution --id "$dist_id" --query 'Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy' --output text)
        if [ "$viewer_protocol" != "redirect-to-https" ] && [ "$viewer_protocol" != "https-only" ]; then
            echo "⚠️  WARNING: CloudFront distribution $dist_id allows HTTP traffic"
        fi
    done
    
    # Check Application Load Balancers
    aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`].[LoadBalancerArn,LoadBalancerName]' --output text | \
    while read lb_arn lb_name; do
        http_listeners=$(aws elbv2 describe-listeners --load-balancer-arn "$lb_arn" --query 'Listeners[?Protocol==`HTTP`]' --output text)
        if [ ! -z "$http_listeners" ]; then
            echo "⚠️  WARNING: Load balancer $lb_name has HTTP listeners"
        fi
    done
}

# Function to check for exposed services
check_exposed_services() {
    echo "Checking for Exposed Services..."
    
    # Check for instances with public IPs
    public_instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,SecurityGroups[*].GroupId]' --output text)
    if [ ! -z "$public_instances" ]; then
        echo "⚠️  WARNING: Instances with public IP addresses found:"
        echo "$public_instances"
    fi
    
    # Check for RDS instances with public access
    public_rds=$(aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier]' --output text)
    if [ ! -z "$public_rds" ]; then
        echo "⚠️  WARNING: Publicly accessible RDS instances: $public_rds"
    fi
    
    # Check for ElastiCache clusters with public access
    public_elasticache=$(aws elasticache describe-cache-clusters --query 'CacheClusters[?contains(PreferredAvailabilityZone, `public`)].[CacheClusterId]' --output text)
    if [ ! -z "$public_elasticache" ]; then
        echo "⚠️  WARNING: Publicly accessible ElastiCache clusters: $public_elasticache"
    fi
}

# Run vulnerability scans
echo "Starting vulnerability scanning..."
scan_security_misconfigurations
echo ""
check_ssl_tls_configuration
echo ""
check_exposed_services
echo ""
echo "Vulnerability scanning completed."
```

#### 3. Security Compliance Testing

**Compliance Validation Script:**
```bash
#!/bin/bash
# compliance_validation.sh

echo "=== Security Compliance Validation ==="

# Function to validate CIS AWS Foundations Benchmark controls
validate_cis_controls() {
    echo "Validating CIS AWS Foundations Benchmark Controls..."
    
    # CIS 1.1 - Avoid the use of the "root" account
    echo "CIS 1.1: Checking root account usage..."
    root_usage=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root --start-time $(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%S) --query 'Events[*].[EventTime,EventName]' --output text)
    if [ ! -z "$root_usage" ]; then
        echo "❌ CIS 1.1 FAIL: Root account usage detected in last 90 days"
    else
        echo "✅ CIS 1.1 PASS: No root account usage in last 90 days"
    fi
    
    # CIS 1.2 - Ensure MFA is enabled for the "root" account
    echo "CIS 1.2: Checking root account MFA..."
    root_mfa=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
    if [ "$root_mfa" = "1" ]; then
        echo "✅ CIS 1.2 PASS: Root account MFA enabled"
    else
        echo "❌ CIS 1.2 FAIL: Root account MFA not enabled"
    fi
    
    # CIS 1.3 - Ensure credentials unused for 90 days or greater are disabled
    echo "CIS 1.3: Checking for unused credentials..."
    aws iam list-users --query 'Users[*].UserName' --output text | \
    while read username; do
        last_used=$(aws iam get-user --user-name "$username" --query 'User.PasswordLastUsed' --output text 2>/dev/null)
        if [ "$last_used" != "None" ] && [ ! -z "$last_used" ]; then
            days_since_use=$(( ($(date +%s) - $(date -d "$last_used" +%s)) / 86400 ))
            if [ $days_since_use -gt 90 ]; then
                echo "❌ CIS 1.3 FAIL: User $username has unused credentials for $days_since_use days"
            fi
        fi
    done
    
    # CIS 2.1 - Ensure CloudTrail is enabled in all regions
    echo "CIS 2.1: Checking CloudTrail configuration..."
    multi_region_trails=$(aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]' --output text)
    if [ -z "$multi_region_trails" ]; then
        echo "❌ CIS 2.1 FAIL: No multi-region CloudTrail found"
    else
        echo "✅ CIS 2.1 PASS: Multi-region CloudTrail enabled"
    fi
    
    # CIS 2.2 - Ensure CloudTrail log file validation is enabled
    echo "CIS 2.2: Checking CloudTrail log file validation..."
    log_validation=$(aws cloudtrail describe-trails --query 'trailList[?LogFileValidationEnabled==`true`]' --output text)
    if [ -z "$log_validation" ]; then
        echo "❌ CIS 2.2 FAIL: CloudTrail log file validation not enabled"
    else
        echo "✅ CIS 2.2 PASS: CloudTrail log file validation enabled"
    fi
    
    # CIS 2.3 - Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
    echo "CIS 2.3: Checking CloudTrail S3 bucket access..."
    aws cloudtrail describe-trails --query 'trailList[*].S3BucketName' --output text | \
    while read bucket_name; do
        if [ ! -z "$bucket_name" ]; then
            public_access=$(aws s3api get-public-access-block --bucket "$bucket_name" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text 2>/dev/null)
            if echo "$public_access" | grep -q "False"; then
                echo "❌ CIS 2.3 FAIL: CloudTrail bucket $bucket_name may be publicly accessible"
            else
                echo "✅ CIS 2.3 PASS: CloudTrail bucket $bucket_name is not publicly accessible"
            fi
        fi
    done
}

# Function to validate NIST controls
validate_nist_controls() {
    echo "Validating NIST Cybersecurity Framework Controls..."
    
    # NIST ID.AM-2: Software platforms and applications within the organization are inventoried
    echo "NIST ID.AM-2: Checking software inventory..."
    config_enabled=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text 2>/dev/null)
    if [ -z "$config_enabled" ] || [ "$config_enabled" = "None" ]; then
        echo "❌ NIST ID.AM-2 FAIL: AWS Config not enabled for asset inventory"
    else
        echo "✅ NIST ID.AM-2 PASS: AWS Config enabled for asset inventory"
    fi
    
    # NIST PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited
    echo "NIST PR.AC-1: Checking identity management..."
    iam_credential_report=$(aws iam generate-credential-report --query 'State' --output text 2>/dev/null)
    if [ "$iam_credential_report" = "COMPLETE" ] || [ "$iam_credential_report" = "STARTED" ]; then
        echo "✅ NIST PR.AC-1 PASS: IAM credential reporting enabled"
    else
        echo "❌ NIST PR.AC-1 FAIL: IAM credential reporting not available"
    fi
    
    # NIST PR.DS-1: Data-at-rest is protected
    echo "NIST PR.DS-1: Checking data-at-rest protection..."
    unencrypted_volumes=$(aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`]' --output text)
    if [ ! -z "$unencrypted_volumes" ]; then
        echo "❌ NIST PR.DS-1 FAIL: Unencrypted EBS volumes found"
    else
        echo "✅ NIST PR.DS-1 PASS: All EBS volumes encrypted"
    fi
    
    # NIST DE.CM-1: The network is monitored to detect potential cybersecurity events
    echo "NIST DE.CM-1: Checking network monitoring..."
    guardduty_enabled=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
    if [ -z "$guardduty_enabled" ] || [ "$guardduty_enabled" = "None" ]; then
        echo "❌ NIST DE.CM-1 FAIL: GuardDuty not enabled for network monitoring"
    else
        echo "✅ NIST DE.CM-1 PASS: GuardDuty enabled for network monitoring"
    fi
}

# Run compliance validation
echo "Starting compliance validation..."
validate_cis_controls
echo ""
validate_nist_controls
echo ""
echo "Compliance validation completed."
```

### Security Testing Checklist

#### Identity and Access Management Testing
- [ ] **Root Account Security**: No access keys, MFA enabled, minimal usage
- [ ] **User Management**: All users have MFA, strong passwords, regular access reviews
- [ ] **Role-Based Access**: Least privilege implemented, temporary credentials used
- [ ] **Policy Validation**: No overly permissive policies, regular policy reviews
- [ ] **Cross-Account Access**: Proper external ID usage, condition-based access

#### Network Security Testing
- [ ] **VPC Configuration**: Proper subnet segmentation, no default VPCs in use
- [ ] **Security Groups**: Least privilege rules, no 0.0.0.0/0 for SSH/RDP
- [ ] **Network ACLs**: Appropriate subnet-level filtering
- [ ] **VPC Flow Logs**: Enabled for all VPCs and subnets
- [ ] **Private Connectivity**: VPC endpoints for AWS services, PrivateLink usage

#### Data Protection Testing
- [ ] **Encryption at Rest**: All storage services encrypted with appropriate keys
- [ ] **Encryption in Transit**: HTTPS/TLS for all communications
- [ ] **Key Management**: Proper KMS key policies, regular key rotation
- [ ] **Data Classification**: Sensitive data identified and properly protected
- [ ] **Backup Security**: Encrypted backups, secure backup storage

#### Monitoring and Detection Testing
- [ ] **CloudTrail**: Enabled in all regions, log file validation enabled
- [ ] **GuardDuty**: Enabled and actively monitoring for threats
- [ ] **Security Hub**: Centralized security findings management
- [ ] **Config**: Configuration compliance monitoring enabled
- [ ] **Custom Monitoring**: Application-specific security monitoring

#### Incident Response Testing
- [ ] **Response Plan**: Documented and tested incident response procedures
- [ ] **Automation**: Automated response capabilities for common scenarios
- [ ] **Communication**: Notification and escalation procedures tested
- [ ] **Forensics**: Log retention and forensic analysis capabilities
- [ ] **Recovery**: Tested recovery procedures and business continuity plans
## Troubleshooting Common Issues

### Identity and Access Management Issues

#### Root Account Security Problems

**Problem**: Root account access keys exist or MFA not enabled
```bash
# Diagnosis: Check root account security status
aws iam get-account-summary \
    --query 'SummaryMap.[AccountAccessKeysPresent,AccountMFAEnabled]' \
    --output table

# Check for recent root account usage
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=root \
    --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S) \
    --query 'Events[*].[EventTime,EventName,SourceIPAddress]' \
    --output table
```

**Solutions:**
- Delete root account access keys immediately
- Enable MFA for root account using hardware token
- Restrict root account usage to essential tasks only
- Monitor root account usage with CloudTrail alerts

#### Overly Permissive IAM Policies

**Problem**: Users or roles have excessive permissions
```bash
# Diagnosis: Find policies with administrative access
aws iam list-policies --scope Local \
    --query 'Policies[*].[PolicyName,Arn]' --output text | \
while read policy_name policy_arn; do
    policy_doc=$(aws iam get-policy-version \
        --policy-arn "$policy_arn" \
        --version-id $(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text) \
        --query 'PolicyVersion.Document' --output json)
    if echo "$policy_doc" | jq -r '.Statement[]' | grep -q '"Effect": "Allow".*"Action": "\*".*"Resource": "\*"'; then
        echo "Policy $policy_name has administrative permissions"
    fi
done

# Check for unused permissions
aws iam generate-service-last-accessed-details \
    --arn $(aws sts get-caller-identity --query Arn --output text) \
    --granularity SERVICE_LEVEL
```

**Solutions:**
- Implement least privilege principle
- Use AWS managed policies where appropriate
- Regular access reviews and permission audits
- Implement permission boundaries for delegated administration

#### Missing Multi-Factor Authentication

**Problem**: Users without MFA enabled
```bash
# Diagnosis: List users without MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
while read username; do
    mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].SerialNumber' --output text)
    if [ -z "$mfa_devices" ]; then
        echo "User $username has no MFA device"
    fi
done
```

**Solutions:**
- Enforce MFA for all users through IAM policies
- Use conditional access policies requiring MFA
- Implement hardware-based MFA for privileged accounts
- Regular MFA compliance auditing and enforcement

### Network Security Issues

#### Overly Permissive Security Groups

**Problem**: Security groups allowing broad access from internet
```bash
# Diagnosis: Find security groups with 0.0.0.0/0 access
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[IpProtocol,FromPort,ToPort]]' \
    --output table

# Check for SSH/RDP access from anywhere
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`22` || FromPort==`3389`)]].[GroupId,GroupName]' \
    --output table
```

**Solutions:**
- Implement least privilege network access
- Use specific IP ranges instead of 0.0.0.0/0
- Implement bastion hosts for administrative access
- Use AWS Systems Manager Session Manager instead of SSH

#### Missing VPC Flow Logs

**Problem**: Network traffic not being logged for security analysis
```bash
# Diagnosis: Check VPC Flow Logs status
aws ec2 describe-flow-logs \
    --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogStatus]' \
    --output table

# Check VPCs without Flow Logs
aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | \
while read vpc_id; do
    flow_logs=$(aws ec2 describe-flow-logs --filters Name=resource-id,Values="$vpc_id" --query 'FlowLogs[*].FlowLogId' --output text)
    if [ -z "$flow_logs" ]; then
        echo "VPC $vpc_id has no Flow Logs enabled"
    fi
done
```

**Solutions:**
- Enable VPC Flow Logs for all VPCs and subnets
- Configure Flow Logs to send to CloudWatch Logs or S3
- Implement automated analysis of Flow Logs for security events
- Set up alerts for suspicious network activity

### Data Protection Issues

#### Unencrypted Data Storage

**Problem**: Data stored without encryption
```bash
# Diagnosis: Check for unencrypted S3 buckets
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null)
    if [ -z "$encryption" ] || [ "$encryption" = "None" ]; then
        echo "Bucket $bucket is not encrypted"
    fi
done

# Check for unencrypted EBS volumes
aws ec2 describe-volumes \
    --query 'Volumes[?Encrypted==`false`].[VolumeId,Size,State,Attachments[0].InstanceId]' \
    --output table

# Check for unencrypted RDS instances
aws rds describe-db-instances \
    --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,Engine,DBInstanceClass]' \
    --output table
```

**Solutions:**
- Enable default encryption for all storage services
- Use AWS KMS for centralized key management
- Implement encryption at rest for all sensitive data
- Regular auditing of encryption status

#### Public Data Exposure

**Problem**: S3 buckets or other resources publicly accessible
```bash
# Diagnosis: Check for public S3 buckets
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    # Check public access block
    public_access=$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text 2>/dev/null)
    if [ -z "$public_access" ] || echo "$public_access" | grep -q "False"; then
        echo "Bucket $bucket may have public access"
    fi
    
    # Check bucket ACL
    public_acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text 2>/dev/null)
    if [ ! -z "$public_acl" ]; then
        echo "Bucket $bucket has public ACL"
    fi
done

# Check for publicly accessible RDS instances
aws rds describe-db-instances \
    --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine]' \
    --output table
```

**Solutions:**
- Enable S3 Block Public Access at account and bucket level
- Regular auditing of public resource exposure
- Implement least privilege access policies
- Use VPC endpoints for private connectivity to AWS services

### Monitoring and Detection Issues

#### Missing Security Monitoring

**Problem**: Security services not enabled or configured properly
```bash
# Diagnosis: Check security service status
echo "CloudTrail Status:"
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,IsLogging,IsMultiRegionTrail,IncludeGlobalServiceEvents]' \
    --output table

echo -e "\nGuardDuty Status:"
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
while read detector_id; do
    if [ ! -z "$detector_id" ]; then
        aws guardduty get-detector --detector-id "$detector_id" \
            --query '[Status,ServiceRole,FindingPublishingFrequency]' \
            --output table
    else
        echo "GuardDuty not enabled"
    fi
done

echo -e "\nSecurity Hub Status:"
aws securityhub describe-hub \
    --query '[HubArn,AutoEnableControls]' \
    --output table 2>/dev/null || echo "Security Hub not enabled"

echo -e "\nConfig Status:"
aws configservice describe-configuration-recorders \
    --query 'ConfigurationRecorders[*].[name,recordingGroup.allSupported]' \
    --output table
```

**Solutions:**
- Enable CloudTrail in all regions with log file validation
- Enable GuardDuty for threat detection
- Configure Security Hub for centralized security findings
- Enable AWS Config for compliance monitoring

#### Insufficient Log Retention

**Problem**: Security logs not retained for adequate period
```bash
# Diagnosis: Check log retention settings
aws logs describe-log-groups \
    --query 'logGroups[*].[logGroupName,retentionInDays]' \
    --output table

# Check CloudTrail log retention
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,S3BucketName,S3KeyPrefix]' \
    --output table
```

**Solutions:**
- Set appropriate log retention periods based on compliance requirements
- Use S3 lifecycle policies for long-term log storage
- Implement log archival to Glacier for cost-effective long-term retention
- Regular review of log retention policies

### Application Security Issues

#### Insecure API Configurations

**Problem**: APIs without proper security controls
```bash
# Diagnosis: Check API Gateway security
aws apigateway get-rest-apis \
    --query 'items[*].[id,name,policy]' \
    --output table

# Check for APIs without authentication
aws apigateway get-rest-apis --query 'items[*].id' --output text | \
while read api_id; do
    resources=$(aws apigateway get-resources --rest-api-id "$api_id" --query 'items[*].id' --output text)
    for resource_id in $resources; do
        methods=$(aws apigateway get-resource --rest-api-id "$api_id" --resource-id "$resource_id" --query 'resourceMethods' --output text 2>/dev/null)
        if [ ! -z "$methods" ]; then
            echo "API $api_id resource $resource_id has methods: $methods"
        fi
    done
done
```

**Solutions:**
- Implement proper authentication and authorization for all APIs
- Use API keys, IAM roles, or Cognito for API access control
- Enable API Gateway logging and monitoring
- Implement rate limiting and throttling

#### Missing Web Application Firewall

**Problem**: Web applications not protected by WAF
```bash
# Diagnosis: Check WAF configuration
aws wafv2 list-web-acls --scope REGIONAL \
    --query 'WebACLs[*].[Name,Id,Description]' \
    --output table

aws wafv2 list-web-acls --scope CLOUDFRONT \
    --query 'WebACLs[*].[Name,Id,Description]' \
    --output table

# Check ALB associations with WAF
aws elbv2 describe-load-balancers \
    --query 'LoadBalancers[?Type==`application`].[LoadBalancerArn,LoadBalancerName]' \
    --output text | \
while read lb_arn lb_name; do
    waf_association=$(aws wafv2 get-web-acl-for-resource --resource-arn "$lb_arn" --query 'WebACL.Name' --output text 2>/dev/null)
    if [ -z "$waf_association" ] || [ "$waf_association" = "None" ]; then
        echo "Load balancer $lb_name has no WAF association"
    fi
done
```

**Solutions:**
- Deploy AWS WAF for all public-facing web applications
- Configure WAF rules for common attack patterns (OWASP Top 10)
- Implement rate limiting and IP reputation rules
- Regular review and tuning of WAF rules

### Incident Response Issues

#### Lack of Incident Response Automation

**Problem**: Manual incident response processes
```bash
# Diagnosis: Check for incident response automation
aws lambda list-functions \
    --query 'Functions[?contains(FunctionName, `incident`) || contains(FunctionName, `response`) || contains(FunctionName, `security`)][FunctionName,Runtime]' \
    --output table

aws ssm list-documents \
    --filters Key=DocumentType,Values=Automation \
    --query 'DocumentIdentifiers[?contains(Name, `incident`) || contains(Name, `response`)][Name,DocumentType]' \
    --output table

# Check for security event notifications
aws sns list-topics \
    --query 'Topics[*].TopicArn' --output text | \
while read topic_arn; do
    topic_name=$(echo "$topic_arn" | cut -d':' -f6)
    if echo "$topic_name" | grep -qi "security\|incident\|alert"; then
        echo "Security notification topic: $topic_arn"
    fi
done
```

**Solutions:**
- Implement automated incident response workflows
- Use AWS Lambda for automated remediation actions
- Create Systems Manager automation documents for common responses
- Set up proper notification and escalation procedures

#### Insufficient Forensic Capabilities

**Problem**: Limited ability to investigate security incidents
```bash
# Diagnosis: Check forensic readiness
echo "CloudTrail Configuration for Forensics:"
aws cloudtrail describe-trails \
    --query 'trailList[*].[Name,LogFileValidationEnabled,EventSelectors[0].ReadWriteType,EventSelectors[0].IncludeManagementEvents]' \
    --output table

echo -e "\nVPC Flow Logs for Network Forensics:"
aws ec2 describe-flow-logs \
    --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestination]' \
    --output table

echo -e "\nEBS Snapshot Capabilities:"
aws ec2 describe-snapshots --owner-ids self \
    --query 'Snapshots[0:5].[SnapshotId,VolumeId,StartTime,State]' \
    --output table
```

**Solutions:**
- Enable comprehensive logging across all services
- Implement log centralization and long-term retention
- Create forensic investigation procedures and tools
- Regular testing of forensic capabilities and procedures
## Post-Review Implementation

### Security Improvement Roadmap

#### 1. Priority-Based Implementation Plan

**Critical Security Issues (Immediate - 0-30 days):**
```yaml
critical_security_fixes:
  identity_access:
    - item: "Remove root account access keys"
      risk_level: "Critical"
      business_impact: "High"
      effort: "Low"
      timeline: "1 day"
      owner: "Security Team"
      
    - item: "Enable MFA for all users"
      risk_level: "Critical"
      business_impact: "High"
      effort: "Medium"
      timeline: "1 week"
      owner: "Identity Team"
      
  data_protection:
    - item: "Enable S3 Block Public Access"
      risk_level: "Critical"
      business_impact: "High"
      effort: "Low"
      timeline: "1 day"
      owner: "Cloud Team"
      
    - item: "Encrypt unencrypted EBS volumes"
      risk_level: "Critical"
      business_impact: "Medium"
      effort: "High"
      timeline: "2 weeks"
      owner: "Infrastructure Team"
      
  monitoring_detection:
    - item: "Enable CloudTrail in all regions"
      risk_level: "Critical"
      business_impact: "High"
      effort: "Low"
      timeline: "1 day"
      owner: "Security Team"
```

**High Priority Issues (30-90 days):**
```yaml
high_priority_fixes:
  network_security:
    - item: "Implement VPC Flow Logs"
      risk_level: "High"
      business_impact: "Medium"
      effort: "Medium"
      timeline: "1 week"
      owner: "Network Team"
      
    - item: "Review and tighten security groups"
      risk_level: "High"
      business_impact: "Medium"
      effort: "High"
      timeline: "4 weeks"
      owner: "Infrastructure Team"
      
  application_security:
    - item: "Deploy AWS WAF for web applications"
      risk_level: "High"
      business_impact: "Medium"
      effort: "Medium"
      timeline: "2 weeks"
      owner: "Application Team"
      
    - item: "Implement secure API authentication"
      risk_level: "High"
      business_impact: "High"
      effort: "High"
      timeline: "6 weeks"
      owner: "Development Team"
```

#### 2. Security Implementation Automation

**Automated Security Deployment Script:**
```bash
#!/bin/bash
# automated_security_deployment.sh

echo "=== Automated Security Implementation ==="

# Function to enable security services
enable_security_services() {
    echo "Enabling core security services..."
    
    # Enable GuardDuty
    echo "Enabling GuardDuty..."
    detector_id=$(aws guardduty create-detector \
        --enable \
        --finding-publishing-frequency FIFTEEN_MINUTES \
        --query 'DetectorId' --output text)
    echo "GuardDuty enabled with detector ID: $detector_id"
    
    # Enable Security Hub
    echo "Enabling Security Hub..."
    aws securityhub enable-security-hub \
        --enable-default-standards \
        --query 'HubArn' --output text
    echo "Security Hub enabled"
    
    # Enable Config
    echo "Enabling AWS Config..."
    # Create Config service role
    aws iam create-role \
        --role-name AWSConfigRole \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "config.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }' 2>/dev/null
    
    aws iam attach-role-policy \
        --role-name AWSConfigRole \
        --policy-arn arn:aws:iam::aws:policy/service-role/ConfigRole
    
    # Create Config configuration recorder
    aws configservice put-configuration-recorder \
        --configuration-recorder name=default,roleARN=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/AWSConfigRole \
        --recording-group allSupported=true,includeGlobalResourceTypes=true
    
    echo "AWS Config enabled"
}

# Function to implement encryption
implement_encryption() {
    echo "Implementing encryption controls..."
    
    # Enable S3 default encryption
    echo "Enabling S3 default encryption..."
    aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
    while read bucket; do
        aws s3api put-bucket-encryption \
            --bucket "$bucket" \
            --server-side-encryption-configuration '{
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }' 2>/dev/null && echo "Encryption enabled for bucket: $bucket"
    done
    
    # Enable EBS encryption by default
    echo "Enabling EBS encryption by default..."
    aws ec2 enable-ebs-encryption-by-default
    echo "EBS default encryption enabled"
}

# Function to configure network security
configure_network_security() {
    echo "Configuring network security..."
    
    # Enable VPC Flow Logs for all VPCs
    echo "Enabling VPC Flow Logs..."
    aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | \
    while read vpc_id; do
        # Check if Flow Logs already exist
        existing_logs=$(aws ec2 describe-flow-logs --filters Name=resource-id,Values="$vpc_id" --query 'FlowLogs[*].FlowLogId' --output text)
        if [ -z "$existing_logs" ]; then
            aws ec2 create-flow-logs \
                --resource-type VPC \
                --resource-ids "$vpc_id" \
                --traffic-type ALL \
                --log-destination-type cloud-watch-logs \
                --log-group-name VPCFlowLogs \
                --deliver-logs-permission-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/flowlogsRole \
                --query 'FlowLogIds[0]' --output text 2>/dev/null && echo "Flow Logs enabled for VPC: $vpc_id"
        fi
    done
}

# Function to set up monitoring and alerting
setup_monitoring_alerting() {
    echo "Setting up monitoring and alerting..."
    
    # Create SNS topic for security alerts
    security_topic_arn=$(aws sns create-topic --name SecurityAlerts --query 'TopicArn' --output text)
    echo "Security alerts topic created: $security_topic_arn"
    
    # Create CloudWatch alarms for security events
    aws cloudwatch put-metric-alarm \
        --alarm-name "Root-Account-Usage" \
        --alarm-description "Alert when root account is used" \
        --metric-name RootAccountUsage \
        --namespace Custom/Security \
        --statistic Sum \
        --period 300 \
        --threshold 1 \
        --comparison-operator GreaterThanOrEqualToThreshold \
        --evaluation-periods 1 \
        --alarm-actions "$security_topic_arn"
    
    echo "Security monitoring alarms created"
}

# Execute security implementation
echo "Starting automated security implementation..."
enable_security_services
echo ""
implement_encryption
echo ""
configure_network_security
echo ""
setup_monitoring_alerting
echo ""
echo "Automated security implementation completed."
```

### Continuous Security Improvement

#### 1. Security Metrics and KPIs

**Security Dashboard Creation:**
```bash
#!/bin/bash
# create_security_dashboard.sh

echo "Creating Security Metrics Dashboard..."

aws cloudwatch put-dashboard \
    --dashboard-name "Security-Metrics" \
    --dashboard-body '{
        "widgets": [
            {
                "type": "metric",
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/GuardDuty", "FindingCount", "DetectorId", "YOUR_DETECTOR_ID" ]
                    ],
                    "view": "timeSeries",
                    "stacked": false,
                    "region": "us-east-1",
                    "title": "GuardDuty Findings",
                    "period": 300
                }
            },
            {
                "type": "metric",
                "x": 12,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        [ "AWS/SecurityHub", "Findings", "ComplianceType", "FAILED" ],
                        [ ".", ".", ".", "PASSED" ]
                    ],
                    "view": "timeSeries",
                    "stacked": false,
                    "region": "us-east-1",
                    "title": "Security Hub Compliance",
                    "period": 300
                }
            },
            {
                "type": "log",
                "x": 0,
                "y": 6,
                "width": 24,
                "height": 6,
                "properties": {
                    "query": "SOURCE \"/aws/cloudtrail\" | fields @timestamp, eventName, sourceIPAddress, userIdentity.type\n| filter eventName like /Console/\n| stats count() by sourceIPAddress\n| sort count desc\n| limit 20",
                    "region": "us-east-1",
                    "title": "Top Console Login Sources",
                    "view": "table"
                }
            }
        ]
    }'

echo "Security dashboard created successfully."
```

#### 2. Regular Security Reviews

**Monthly Security Review Script:**
```bash
#!/bin/bash
# monthly_security_review.sh

echo "=== Monthly Security Review ==="
echo "Review Date: $(date)"

# Security posture summary
echo -e "\n=== Security Posture Summary ==="

# GuardDuty findings summary
echo "GuardDuty Findings (Last 30 days):"
aws guardduty list-detectors --query 'DetectorIds[0]' --output text | \
while read detector_id; do
    if [ ! -z "$detector_id" ]; then
        aws guardduty get-findings-statistics \
            --detector-id "$detector_id" \
            --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]},"updatedAt":{"Gte":'$(date -d "30 days ago" +%s)'000}}}' \
            --finding-statistic-types COUNT_BY_SEVERITY \
            --query 'FindingStatistics.CountBySeverity' \
            --output table
    fi
done

# Security Hub compliance summary
echo -e "\nSecurity Hub Compliance Summary:"
aws securityhub get-findings \
    --filters '{"WorkflowStatus":[{"Value":"NEW","Comparison":"EQUALS"}],"UpdatedAt":[{"Start":"'$(date -d "30 days ago" +%Y-%m-%d)'T00:00:00.000Z","End":"'$(date +%Y-%m-%d)'T23:59:59.999Z"}]}' \
    --query 'Findings[*].Severity.Label' \
    --output text | sort | uniq -c

# IAM security metrics
echo -e "\n=== IAM Security Metrics ==="
echo "Users without MFA:"
aws iam list-users --query 'Users[*].UserName' --output text | \
while read username; do
    mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].SerialNumber' --output text)
    if [ -z "$mfa_devices" ]; then
        echo "  - $username"
    fi
done

# Encryption compliance
echo -e "\n=== Encryption Compliance ==="
unencrypted_volumes=$(aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`]' --output text | wc -l)
echo "Unencrypted EBS volumes: $unencrypted_volumes"

unencrypted_buckets=0
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
while read bucket; do
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null)
    if [ -z "$encryption" ] || [ "$encryption" = "None" ]; then
        ((unencrypted_buckets++))
    fi
done
echo "Unencrypted S3 buckets: $unencrypted_buckets"

# Generate action items
echo -e "\n=== Action Items ==="
cat > monthly_security_actions.txt << 'EOF'
Monthly Security Review Action Items

High Priority:
- [ ] Review and remediate new GuardDuty findings
- [ ] Address Security Hub compliance failures
- [ ] Enable MFA for users without it
- [ ] Encrypt unencrypted resources

Medium Priority:
- [ ] Review and update security group rules
- [ ] Audit IAM policies for least privilege
- [ ] Update incident response procedures
- [ ] Review access logs for anomalies

Low Priority:
- [ ] Update security training materials
- [ ] Review and update security documentation
- [ ] Plan next security assessment
- [ ] Evaluate new security services and features
EOF

echo "Monthly security review completed. Check monthly_security_actions.txt for action items."
```

### Security Training and Awareness

#### 1. Security Training Program

**Security Training Curriculum:**
```yaml
security_training_program:
  foundation_level:
    duration: "1 day"
    audience: "All employees"
    topics:
      - "AWS Shared Responsibility Model"
      - "Basic security principles and best practices"
      - "Password security and MFA"
      - "Phishing and social engineering awareness"
    hands_on_labs:
      - "Setting up MFA for AWS accounts"
      - "Identifying phishing attempts"
      - "Secure password management"
    
  technical_level:
    duration: "3 days"
    audience: "Technical staff"
    topics:
      - "AWS security services and implementation"
      - "Identity and access management"
      - "Network security and encryption"
      - "Incident response procedures"
    hands_on_labs:
      - "Configuring IAM policies and roles"
      - "Setting up security monitoring"
      - "Implementing encryption"
      - "Incident response simulation"
    
  advanced_level:
    duration: "5 days"
    audience: "Security professionals"
    topics:
      - "Advanced threat detection and response"
      - "Security architecture and design"
      - "Compliance and governance"
      - "Security automation and orchestration"
    hands_on_labs:
      - "Advanced GuardDuty and Security Hub configuration"
      - "Custom security automation development"
      - "Penetration testing and vulnerability assessment"
      - "Forensic analysis and investigation"

ongoing_training:
  monthly_sessions:
    - "Security threat landscape updates"
    - "New AWS security features and services"
    - "Incident review and lessons learned"
  
  quarterly_workshops:
    - "Tabletop incident response exercises"
    - "Security architecture reviews"
    - "Compliance audit preparation"
  
  annual_events:
    - "Security conference attendance"
    - "AWS re:Inforce security sessions"
    - "Internal security summit"
```

## Additional Resources

### Official AWS Documentation

#### Core Security Resources
- **[Security Pillar Whitepaper](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)** - Comprehensive security guidance
- **[AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)** - Security architecture patterns
- **[AWS Security Documentation](https://docs.aws.amazon.com/security/)** - Complete security service documentation
- **[AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)** - Understanding security responsibilities

#### Service-Specific Security Guides
- **[IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)** - Identity and access management
- **[VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)** - Network security guidance
- **[S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)** - Data protection and access control
- **[RDS Security](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html)** - Database security configuration

### AWS Security Services

#### Detection and Response
- **[Amazon GuardDuty](https://aws.amazon.com/guardduty/)** - Threat detection service
- **[AWS Security Hub](https://aws.amazon.com/security-hub/)** - Centralized security findings
- **[AWS CloudTrail](https://aws.amazon.com/cloudtrail/)** - API logging and monitoring
- **[Amazon Detective](https://aws.amazon.com/detective/)** - Security investigation service

#### Identity and Access Management
- **[AWS IAM](https://aws.amazon.com/iam/)** - Identity and access management
- **[AWS IAM Identity Center](https://aws.amazon.com/single-sign-on/)** - Centralized access management
- **[Amazon Cognito](https://aws.amazon.com/cognito/)** - User identity and authentication
- **[AWS Directory Service](https://aws.amazon.com/directoryservice/)** - Managed directory services

#### Data Protection
- **[AWS KMS](https://aws.amazon.com/kms/)** - Key management service
- **[AWS Certificate Manager](https://aws.amazon.com/certificate-manager/)** - SSL/TLS certificate management
- **[AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)** - Secrets management
- **[Amazon Macie](https://aws.amazon.com/macie/)** - Data discovery and classification

#### Infrastructure Protection
- **[AWS WAF](https://aws.amazon.com/waf/)** - Web application firewall
- **[AWS Shield](https://aws.amazon.com/shield/)** - DDoS protection
- **[AWS Network Firewall](https://aws.amazon.com/network-firewall/)** - Network protection
- **[Amazon Inspector](https://aws.amazon.com/inspector/)** - Vulnerability assessment

### Compliance and Governance

#### Compliance Programs
- **[AWS Compliance Programs](https://aws.amazon.com/compliance/programs/)** - Certification and attestation programs
- **[AWS Artifact](https://aws.amazon.com/artifact/)** - Compliance reports and agreements
- **[AWS Audit Manager](https://aws.amazon.com/audit-manager/)** - Audit preparation and management
- **[AWS Config](https://aws.amazon.com/config/)** - Configuration compliance monitoring

#### Security Frameworks
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Cybersecurity best practices
- **[CIS Controls](https://www.cisecurity.org/controls/)** - Critical security controls
- **[ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)** - Information security management
- **[SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)** - Security and availability controls

### Training and Certification

#### AWS Security Training
- **[AWS Security Learning Path](https://aws.amazon.com/training/learning-paths/security/)** - Comprehensive security training
- **[AWS Security Specialty Certification](https://aws.amazon.com/certification/certified-security-specialty/)** - Advanced security certification
- **[AWS Security Workshops](https://workshops.aws/)** - Hands-on security labs
- **[AWS Security Blog](https://aws.amazon.com/blogs/security/)** - Latest security updates and best practices

#### External Security Training
- **[SANS Security Training](https://www.sans.org/)** - Information security training
- **[ISC2 Certifications](https://www.isc2.org/)** - Security professional certifications
- **[CompTIA Security+](https://www.comptia.org/certifications/security)** - Foundational security certification
- **[CISSP](https://www.isc2.org/Certifications/CISSP)** - Advanced security professional certification

### Community and Support

#### AWS Security Community
- **[AWS Security Forums](https://forums.aws.amazon.com/forum.jspa?forumID=196)** - Community discussions
- **[AWS re:Post Security](https://repost.aws/topics/security)** - Q&A platform
- **[AWS Security User Groups](https://aws.amazon.com/developer/community/usergroups/)** - Local security communities
- **[AWS Security Partners](https://aws.amazon.com/security/partner-solutions/)** - Security solution providers

#### Professional Services
- **[AWS Professional Services](https://aws.amazon.com/professional-services/)** - Security consulting and implementation
- **[AWS Security Competency Partners](https://aws.amazon.com/security/partner-solutions/)** - Certified security partners
- **[AWS Managed Services](https://aws.amazon.com/managed-services/)** - Managed security operations

---

## Conclusion

Conducting a comprehensive Well-Architected Security review is essential for protecting your data, systems, and assets in the cloud. This guide provides a structured approach to assess your current security posture, identify vulnerabilities, and implement robust security controls across all seven domains of the Security pillar.

### Key Success Factors:
1. **Comprehensive Assessment**: Thoroughly evaluate all aspects of security including identity, network, data, and application security
2. **Risk-Based Approach**: Prioritize security improvements based on risk level and business impact
3. **Defense in Depth**: Implement multiple layers of security controls across all architectural layers
4. **Continuous Monitoring**: Establish ongoing security monitoring and threat detection capabilities
5. **Incident Preparedness**: Develop and test incident response procedures and automation
6. **Cultural Integration**: Build security awareness and responsibility throughout the organization

### Next Steps:
1. Complete the Well-Architected Security review using this guide
2. Prioritize security improvements based on risk assessment
3. Implement critical security fixes immediately
4. Develop a comprehensive security improvement roadmap
5. Establish continuous security monitoring and improvement processes
6. Conduct regular security training and awareness programs
7. Schedule periodic security reviews and assessments

Remember that security is not a destination but a continuous journey. The threat landscape evolves constantly, and your security posture must evolve with it. Regular reviews, continuous monitoring, and ongoing improvement are essential for maintaining strong security in the cloud.

For complex security challenges or specialized requirements, consider engaging AWS Professional Services or certified security partners who can provide expert guidance tailored to your specific needs and compliance requirements.

The full library of Well Architected Framework guides are available here:

1. **Cost Optimization** - [Cost Optimization Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-cost-pillar)
2. **Reliability** - [Reliability Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-reliability-pillar)
3. **Security** - [Security Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-security-pillar)
4. **Performance Efficiency** - [Performance Efficiency Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-performance-pillar)
5. **Operational Excellence** - [Operational Excellence Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-operational-excellence-pillar)
6. **Sustainability** - [Sustainability Pillar Guide](https://github.com/rushealy-aws/well-architected-guide-sustainability-pillar)

Each guide follows the same comprehensive structure and includes:
- Detailed pillar-specific content based on official AWS documentation
- Step-by-step review processes using the AWS Well-Architected Tool
- Practical assessment scripts and automation tools
- Troubleshooting guides and best practices
- Implementation roadmaps and continuous improvement processes
- Extensive resources and references

