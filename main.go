// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io/ioutil"
// 	"strings"
// )

// type Misconfiguration struct {
// 	Type          string                 `json:"Type"`
// 	ID            string                 `json:"ID"`
// 	AVDID         string                 `json:"AVDID"`
// 	Title         string                 `json:"Title"`
// 	Description   string                 `json:"Description"`
// 	Message       string                 `json:"Message"`
// 	Resolution    string                 `json:"Resolution"`
// 	Severity      string                 `json:"Severity"`
// 	PrimaryURL    string                 `json:"PrimaryURL"`
// 	References    []string               `json:"References"`
// 	Status        string                 `json:"Status"`
// 	Layer         map[string]interface{} `json:"Layer"`
// 	CauseMetadata struct {
// 		Resource string `json:"Resource"`
// 		Provider string `json:"Provider"`
// 		Service  string `json:"Service"`
// 		Code     struct {
// 			Lines interface{} `json:"Lines"`
// 		} `json:"Code"`
// 	} `json:"CauseMetadata"`
// }

// func main() {
// 	jsonData := `
// {
//   "Misconfigurations": [
//     {
//       "Type": "AWS",
//       "ID": "AVD-AWS-0131",
//       "AVDID": "AVD-AWS-0131",
//       "Title": "Instance with unencrypted block device.",
//       "Description": "Block devices should be encrypted to ensure sensitive data is held securely at rest.",
//       "Message": "Root block device is not encrypted.",
//       "Resolution": "Turn on encryption for all block devices",
//       "Severity": "HIGH",
//       "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0131",
//       "References": [
//         "https://avd.aquasec.com/misconfig/avd-aws-0131"
//       ],
//       "Status": "FAIL",
//       "Layer": {},
//       "CauseMetadata": {
//         "Resource": "arn:aws:ec2:us-west-2:accountId:volume/vol-id",
//         "Provider": "aws",
//         "Service": "ec2",
//         "Code": {
//           "Lines": null
//         }
//       }
//     }
//   ]
// }
// `

// 	var data struct {
// 		Misconfigurations []Misconfiguration `json:"Misconfigurations"`
// 	}

// 	err := json.Unmarshal([]byte(jsonData), &data)
// 	if err != nil {
// 		fmt.Println("Error parsing JSON data:", err)
// 		return
// 	}

// 	terraformCode := ""
// 	for _, misconfiguration := range data.Misconfigurations {
// 		if misconfiguration.Title == "Instance with unencrypted block device." {
// 			resourceName := strings.ReplaceAll(misconfiguration.CauseMetadata.Resource, ":", "_")
// 			terraformCode += fmt.Sprintf(`
// 				resource "aws_instance" "%s" {

//   					ebs_block_device {
//     					encrypted = true
//   					}

// 				}
// 			`, resourceName)
// 		}
// 	}

// 	filePath := "/mnt/c/Users/puneeth.sharma_averl/gitaverlon/remediate/remediation.tf"
// 	err = ioutil.WriteFile(filePath, []byte(terraformCode), 0644)
// 	if err != nil {
// 		fmt.Println("Error writing Terraform file:", err)
// 		return
// 	}

// 	fmt.Println("Remediation is at ", filePath, "go and check...")
// }

package main

import (
	"fmt"
	"io/ioutil"
	"strings"
)

//Provide Terraform code (or AWS CLI, CF) to resolve misconfiguration "Ensure that port 9042 for cassandra client is not public" and i have security group for which we need to make changes using terraform

//get the terraform code from browser and paste under terraformCode and misconfiguration in below misconfiguration section to get the updated terraform code with required security group

func main() {
	terraformCode := `resource "aws_security_group" "cassandra_client" {
		name        = "intern bastion host"
		description = "Security group for Cassandra client"
		security_group_id = security-group-id
		
		ingress {
		  from_port   = 9042
		  to_port     = 9042
		  protocol    = "tcp"
		  cidr_blocks = ["your_ip_address/32"]
		}
		ingress {
		  protocol    = "-1"
		  cidr_blocks = ["your_ip_address/32"]
		}
	  }`

	misconfiguration := `{
		"Type": "AWS",
		"ID": "AVD-AWS-34604",
		"AVDID": "AVD-AWS-34604",
		"Title": "Ensure that port 9042 for cassandra client is not public",
		"Description": "TCP port 9042 for cassandra client must be private and should not be open to public.",
		"Message": "Port 9042 is open to public",
		"Namespace": "builtin.aws.ec2.aws34604",
		"Query": "deny",
		"Resolution": "Port 9042 for cassandra internode should be private",
		"Severity": "HIGH",
		"PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-34604",
		"References": [
		  "https://avd.aquasec.com/misconfig/avd-aws-34604"
		],
		"Status": "FAIL",
		"Layer": {},
		"CauseMetadata": {
		  "Resource": "arn:aws:ec2:us-west-2:accountId:security-group/sg-id",
		  "Provider": "aws",
		  "Service": "ec2",
		  "Code": {
			"Lines": null
		  }
		}
	  }`

	securityGroupID := extractSecurityGroupID(misconfiguration)
	updatedTerraformCode := replaceSecurityGroupID(terraformCode, securityGroupID)

	// fmt.Println(updatedTerraformCode)
	filePath := "/mnt/c/Users/puneeth.sharma_averl/gitaverlon/remediate/remediation.tf"
	err := ioutil.WriteFile(filePath, []byte(updatedTerraformCode), 0644)
	if err != nil {
		fmt.Println("Error writing Terraform file:", err)
		return
	}

	fmt.Println("Remediation is at ", filePath, "go and check...")
}

func extractSecurityGroupID(misconfiguration string) string {

	startIndex := strings.Index(misconfiguration, "security-group/") + len("security-group/")
	endIndex := strings.Index(misconfiguration[startIndex:], `"`) + startIndex

	securityGroupID := misconfiguration[startIndex:endIndex]

	return securityGroupID
}

func replaceSecurityGroupID(terraformCode, securityGroupID string) string {
	//Replace the placeholder with dummy security group id in terraform code of chatgpt
	placeholder := "security-group-id"
	updatedTerraformCode := strings.Replace(terraformCode, placeholder, securityGroupID, 1)

	return updatedTerraformCode
}
