package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/wardviaene/golang-for-devops-course/ssh-demo"
)

const location = "westus"

func main(){
	var (
		token azcore.TokenCredential
		pubKey string
		err error
	)

	ctx := context.Background()
	subscriptionId:= os.Getenv("SUBSCRIPTION_ID")

	if len(subscriptionId) == 0{
		log.Printf("No subscription id is provided\n")
		os.Exit(1)
	}

	if pubKey, err = generateKey(); err != nil {
		log.Printf("Genrate Key error: %v", err)
		os.Exit(1)
	}

	if token, err = getToken(); err != nil{
		log.Printf("Token Generate error: %v", err)
		os.Exit(1)
	}

	if err = launchInstance(ctx, subscriptionId, token, &pubKey); err != nil {
		log.Printf("Lanuch Instance error: %v", err)
		os.Exit(1)
	}
}

func generateKey() (string, error){
	var (
		privateKey []byte
		publicKey []byte
		err error
	)

	if privateKey, publicKey, err = ssh.GenerateKeys(); err != nil {
		return "", fmt.Errorf("generate key error: %v", err)
	}

	if err = os.WriteFile("myKey.pem", privateKey, 0600); err != nil{
		return "", fmt.Errorf("private key error: %v", err)
	}

	if err = os.WriteFile("myKey.pub", publicKey, 0644); err != nil{
		return "", fmt.Errorf("public key error: %v", err)
	}

	return string(publicKey), nil
}

func getToken() (azcore.TokenCredential, error){
	token, err := azidentity.NewAzureCLICredential(nil)
	if err != nil{
		return token, fmt.Errorf("newAzureCLICredential error: %v", err)
	}
	return token, nil
}

func launchInstance(ctx context.Context, subscriptionId string, cred azcore.TokenCredential, publicKey *string) error{
	// resoure group created
	resourceGroupClient, err := armresources.NewResourceGroupsClient(subscriptionId, cred, nil)
	if err != nil{
		return fmt.Errorf("NewResourceGroupsClient error: %v", err)
	}

	resourceGroupParams := armresources.ResourceGroup{
		Location: to.Ptr(location),
	}

	resourceGroupResp, err := resourceGroupClient.CreateOrUpdate(ctx, "go-demo", resourceGroupParams, nil)
	if err != nil {
		return fmt.Errorf("createOrUpdate error : %v", err)
	}

	// vnet created
	virtualNetworkClient, err := armnetwork.NewVirtualNetworksClient(subscriptionId, cred, nil)
	if err != nil {
		return fmt.Errorf("newVirtualNetworksClient error : %v", err)
	}

	vnet, found, err := findVNet(ctx, *resourceGroupResp.Name, "go-demo", virtualNetworkClient)
	if err != nil {
		return fmt.Errorf("findVNet() error: %v", err)
	}

	if !found {
		vnetPollerResp, err := virtualNetworkClient.BeginCreateOrUpdate(
			ctx,
			*resourceGroupResp.Name,
			"go-demo",
			armnetwork.VirtualNetwork{
				Location: to.Ptr(location),
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					AddressSpace: &armnetwork.AddressSpace{
						AddressPrefixes: []*string{
							to.Ptr("10.1.0.0/16"),
						},
					},
				},
			},
		nil)
	
		if err != nil{
			return fmt.Errorf("beginCreateOrUpdate error: %v", err)
		}
	
		vnetResp, err := vnetPollerResp.PollUntilDone(ctx, nil)
		if err != nil {
			return fmt.Errorf("pollUntilDone error : %v", err) 
		}

		vnet = vnetResp.VirtualNetwork
	}

	// subnet created
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionId, cred, nil)
	if err != nil{
		return fmt.Errorf("newSubnetsClient error: %v", err)
	}

	subnetPollerResp, err := subnetClient.BeginCreateOrUpdate(
		ctx,
		*resourceGroupResp.Name,
		*vnet.Name,
		"go-demo",
		armnetwork.Subnet{
			Properties: &armnetwork.SubnetPropertiesFormat{
				AddressPrefix: to.Ptr("10.1.0.0/24"),
			},
		},
	nil)

	if err != nil{
		return fmt.Errorf("subnetClient.BeginCreateOrUpdate error: %v", err)
	}

	subnetResponse, err := subnetPollerResp.PollUntilDone(ctx, nil)

	if err != nil{
		return fmt.Errorf("subnetPollerResp.PollUntilDone error: %v", err)
	}


	// public IP address created
	publicIpAddressClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionId, cred, nil)
	if err != nil{
		return fmt.Errorf("newPublicIPAddressesClient error: %v", err)
	}

	publicIpPollerResp, err := publicIpAddressClient.BeginCreateOrUpdate(
		ctx,
		*resourceGroupResp.Name,
		"go-demo",
		armnetwork.PublicIPAddress{
			Location: to.Ptr(location),
			Properties: &armnetwork.PublicIPAddressPropertiesFormat{
				PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
			},
		},
		nil,
	)

	if err != nil {
		return fmt.Errorf("publicIpAddressClient.BeginCreateOrUpdate error: %v", err)
	}

	punlicIPAddressResp, err := publicIpPollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("publicIpPollerResp.PollUntilDone error: %v", err) 
	}

	// netwrok security group
	networkSecurityGroupClient, err := armnetwork.NewSecurityGroupsClient(subscriptionId, cred, nil)
	if err != nil {
		return fmt.Errorf("armnetwork.NewSecurityGroupsClient error: %v", err)
	}

	networkSecurityPollerResp, err := networkSecurityGroupClient.BeginCreateOrUpdate(
		ctx,
		*resourceGroupResp.Name,
		"go-demo",
		armnetwork.SecurityGroup{
			Location: to.Ptr(location),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{
				SecurityRules: []*armnetwork.SecurityRule{
					{
						Name: to.Ptr("allow-ssh"),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							SourceAddressPrefix: to.Ptr("0.0.0.0/0"),
							SourcePortRange: to.Ptr("*"),
							DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
							DestinationPortRange: to.Ptr("22"),
							Protocol: to.Ptr(armnetwork.SecurityRuleProtocolTCP),
							Access: to.Ptr(armnetwork.SecurityRuleAccessAllow),
							Description: to.Ptr("allow ssh on port 22"),
							Direction: to.Ptr(armnetwork.SecurityRuleDirectionInbound),
							Priority: to.Ptr(int32(1001)),
						},
					},
				},
			},
		},
		nil,
	)

	if err != nil {
		return fmt.Errorf("networkSecurityGroupClient.BeginCreateOrUpdate error: %v", err)
	}

	networkSecurityGroupResponse, err := networkSecurityPollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("networkSecurityPollerResp.PollUntilDone error: %v", err)
	}

	// interface created
	interfaceClient, err := armnetwork.NewInterfacesClient(subscriptionId, cred, nil)
	if err != nil {
		return fmt.Errorf("armnetwork.NewInterfacesClient error: %v", err)
	}

	interfacePollerResp, err := interfaceClient.BeginCreateOrUpdate(
		ctx,
		*resourceGroupResp.Name,
		"go-demo",
		armnetwork.Interface{
			Location: to.Ptr(location),
			Properties: &armnetwork.InterfacePropertiesFormat{
				NetworkSecurityGroup: &armnetwork.SecurityGroup{
					ID: networkSecurityGroupResponse.ID,
				},
				IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
					{
						Name: to.Ptr("go-demo"),
						Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
							PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
							Subnet: &armnetwork.Subnet{
								ID: subnetResponse.ID,
							},
							PublicIPAddress: &armnetwork.PublicIPAddress{
								ID: punlicIPAddressResp.ID,
							},
						},
					},
				},
			},
		},
		nil,
	)

	if err != nil {
		return fmt.Errorf("interfaceClient.BeginCreateOrUpdate error: %v", err)
	}

	networkInterfaceResp, err := interfacePollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("interfacePollerResp.PollUntilDone error: %v", err)
	}

	// create virtual machine
	fmt.Println("Creating Vitual Machine ...........")
	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionId, cred, nil)
	if err != nil {
		return fmt.Errorf("armcompute.NewVirtualMachinesClient error: %v", err)
	}

	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(location),
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					// Offer:     to.Ptr("WindowsServer"),
					// Publisher: to.Ptr("MicrosoftWindowsServer"),
					// SKU:       to.Ptr("2019-Datacenter"),
					// Version:   to.Ptr("latest"),
					
					Offer:     to.Ptr("UbuntuServer"),
					Publisher: to.Ptr("Canonical"),
					SKU:       to.Ptr("18.04-LTS"),
					Version:   to.Ptr("latest"),
				},
				OSDisk: &armcompute.OSDisk{
					Name:         to.Ptr("go-demo"),
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS), // OSDisk type Standard/Premium HDD/SSD
					},
					DiskSizeGB: to.Ptr[int32](50), // default 127G
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes("Standard_B1s")), // VM size include vCPUs,RAM,Data Disks,Temp storage.
			},
			OSProfile: &armcompute.OSProfile{ //
				ComputerName:  to.Ptr("go-demo"),
				AdminUsername: to.Ptr("demo"),
				LinuxConfiguration: &armcompute.LinuxConfiguration{
					DisablePasswordAuthentication: to.Ptr(true),
					SSH: &armcompute.SSHConfiguration{
						PublicKeys: []*armcompute.SSHPublicKey{
							{
								Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", "demo")),
								KeyData: publicKey,
							},
						},
					},
				},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: networkInterfaceResp.ID,
					},
				},
			},
		},
	}

	vmPollerResponse, err := vmClient.BeginCreateOrUpdate(ctx, *resourceGroupResp.Name, "go-demo", parameters, nil)
	if err != nil {
		return fmt.Errorf("vmClient.BeginCreateOrUpdate error: %v", err)
	}

	vmResponse, err := vmPollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("vmPollerResponse error: %v", err)
	}

	fmt.Printf("VM Id : %s\n", *vmResponse.ID)

	return nil
}

func findVNet(ctx context.Context, resourceGroupName, vnetName string, vnetClient *armnetwork.VirtualNetworksClient) (armnetwork.VirtualNetwork, bool, error){
	vnet, err := vnetClient.Get(ctx, resourceGroupName, vnetName, nil)
	if err != nil {
		var errorResponse *azcore.ResponseError
		if errors.As(err, &errorResponse) && errorResponse.ErrorCode == "ResourceNotFound"{
			return vnet.VirtualNetwork, false, nil
		}
		return vnet.VirtualNetwork, false, err
	}
	return vnet.VirtualNetwork, true, nil
}
