package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	//"os/exec"
)

type Instance struct {
	name           string
	ip             string
	dns            string
	securityGroups []*ec2.GroupIdentifier
}

func getName(tags []*ec2.Tag) string {
	var name string
	for _, element := range tags {
		if *element.Key == "Name" {
			name = *element.Value
		}
	}
	return name
}

// Given instance object lets parse out important info
func parseInstanceInfo(inst *ec2.Instance) Instance {
	instanceInfo := Instance{}
	// Grab these pointers first and nil check them
	ip := inst.PublicIpAddress
	dns := inst.PublicDnsName
	sg := inst.SecurityGroups
	instanceInfo.name = getName(inst.Tags)

	// Do nil checks or go explodes then deref to get values
	if ip != nil {
		instanceInfo.ip = *inst.PublicIpAddress
	}
	if dns != nil {
		instanceInfo.dns = *inst.PublicDnsName
	}
	if sg != nil {
		instanceInfo.securityGroups = inst.SecurityGroups
	}

	return instanceInfo
}

func main() {
	// Create an EC2 service object in the "us-west-2" region
	// Note that you can also configure your region globally by
	// exporting the AWS_REGION environment variable
	svc := ec2.New(session.New(), &aws.Config{Region: aws.String("us-east-1")})

	// Call the DescribeInstances Operation
	resp, err := svc.DescribeInstances(nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("> Number of reservation sets: ", len(resp.Reservations))

	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			instanceInfo := parseInstanceInfo(inst)
			fmt.Println(instanceInfo)
		}
	}
}
