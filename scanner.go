package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"os/exec"
)

type Instance struct {
	name           string
	ip             string
	dns            string
	securityGroups []*ec2.GroupIdentifier
}

func getName(tags []*ec2.Tag) string {
	for _, element := range tags {
		if *element.Key == "Name" {
			return *element.Value
		}
	}
	return ""
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

func scanHost(host Instance) {
	cmd := exec.Command("nmap", "-Pn", "-n", "-F", host.ip)
	stdout, err := cmd.Output()

	if err != nil {
		println(err.Error())
		return
	}

	print(string(stdout))
	fmt.Println("\n-----------------------")
}

func main() {
	svc := ec2.New(session.New(), &aws.Config{Region: aws.String("us-east-1")})

	// Call the DescribeInstances Operation
	resp, err := svc.DescribeInstances(nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("> Number of reservation sets: ", len(resp.Reservations))

	for idx := range resp.Reservations {
		for _, inst := range resp.Reservations[idx].Instances {
			// for each instance lets parse out the info we want
			instanceInfo := parseInstanceInfo(inst)
			fmt.Println("Processing: ", instanceInfo.name)
			scanHost(instanceInfo)
		}
	}
}
