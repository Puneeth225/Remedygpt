resource "aws_security_group" "cassandra_client" {
		name        = "intern bastion host"
		description = "Security group for Cassandra client"
		security_group_id = sg-id
		
		ingress {
		  from_port   <= 9042
		  to_port     >= 9042
		  protocol    = "tcp"
		  cidr_blocks = ["your_ip_address/32"]
		}
		ingress {
		  protocol    = "-1"
		  cidr_blocks = ["your_ip_address/32"]
		}
	  }