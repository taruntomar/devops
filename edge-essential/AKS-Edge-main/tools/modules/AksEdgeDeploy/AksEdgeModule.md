# AksEdgeDeploy Module

## Powershell Commands with Alias

<details><summary>Connect-AideArc</summary>

This command invokes Connect-AideArcServer which installs and connects Azure Arc Connected machine agent to Arc-enabled Server. Then it invokes Connect-AideArcKubernetes to connect the kubernetes cluster running on the machine (should be running control plane) to Arc-enabled Kubernetes.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Connect-AideArcKubernetes</summary>

This command connects the kubernetes cluster running on the machine (should be running control plane) to Arc-enabled Kubernetes.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Connect-AideArcServer</summary>

This command installs and connects Azure Arc Connected machine agent to Arc-enabled Server. The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Disconnect-AideArc</summary>

This command invokes Disconnect-AideArcServer which disconnects from Arc-enabled Server, if connected.Then it invokes Disconnect-AideArcKubernetes to disconnect from Arc-enabled Kubernetes,if connected.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Disconnect-AideArcKubernetes</summary>

This command disconnects from Arc-enabled Kubernetes,if connected.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Disconnect-AideArcServer</summary>

This command disconnects from Arc-enabled Server, if connected.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Enter-AideArcSession</summary>

Logs into Azure using the service principal credentials supplied in the json file (Azure.Auth.ServicePrincipalId and Azure.Auth.Password). </details>

<details><summary>Exit-AideArcSession</summary>

Logs out of Azure session and clears account cache. </details>

<details><summary>Format-AideJson</summary>

Pretty formats the input json. Based on "https://github.com/PowerShell/PowerShell/issues/2736" </details>

<details><summary>Get-AideArcClusterName</summary>

This command returns the cluster name for the deployed cluster. If the user has specified Clustername in the aide-userconfig.json, the same is returned.If there is no user specifcation, it returns the clustername as hostname-k8s or hostname-k3s based on the kubernetes flavour installed. </details>

<details><summary>Get-AideArcKubernetesServiceToken</summary>

This command the service account token of the aksedge-admin-user from the deployed cluster. It also stores the same value in a servicetoken.txt file. </details>

<details><summary>Get-AideArcServerInfo</summary>

This command returns Arc connection information for Arc-enabled server instance from the local IMDS endpoint. </details>

<details><summary>Get-AideArcServerSMI</summary>

This command the System Managed Identity access token for the Arc-enabled Server instance, queried from the local IMDS end point. </details>

<details><summary>Get-AideHostPcInfo</summary>

Prints the relevant HostPC information such as OS information, available Free/Total CPU/Memory on the console output. </details>

<details><summary>Get-AideInfra</summary>

Returns a coded string for the host OS information including whether its Azure VM or regular VM </details>

<details><summary>Get-AideMsiVersion</summary>

Checks and returns the AksEdge Msi version. This is same as the AksEdge module version. (Get-Module AksEdge -ListAvailable).Version </details>

<details><summary>Get-AideUserConfig</summary>

Returns the PSCustomObject of the UserConfig Json including the embedded AksEdge config data. </details>

<details><summary>Initialize-AideArc</summary>

This command checks and installs Azure CLI by invoking Install-AideAzCli and validates the Azure configuration such as resource group, resource provider status using the service principal credentials.. </details>

<details><summary>Install-AideArcServer</summary>

This command tests if the connected machine agent is installed and installs using script from "https://aka.ms/azcmagent-windows".This also sets up for auto update via Microsoft Update. </details>

<details><summary>Install-AideAzCli</summary>

Checks if Azure CLI is installed (az) and installs the latest version of Azure CLI from "https://aka.ms/installazurecliwindows". This also checks and installs the following extensions"connectedmachine", "connectedk8s", "customlocation", "k8s-extension" </details>

<details><summary>Install-AideMsi</summary>

Checks and installs AksEdge Msi flavour specified in the aide-userconfig.json. When the AksEdgeProduct is specified, it installs the latest available versionusing the aka.ms links. When the AksEdgeProductUrl is specified, it installs from that specific Url. The Url can also be a network file share. </details>

<details><summary>Invoke-AideDeployment</summary>

Checks the input json configuration and invokes the New-AksEdgeDeployment. </details>

<details><summary>Invoke-AideLinuxVmShell (mars)</summary>

Invokes the AksEdge Linux VM Shell </details>

<details><summary>New-AideVmSwitch</summary>

Creates the external VM Switch on the specified net adapter </details>

<details><summary>Read-AideUserConfig</summary>

Reads from the User Config json file and updates the PSCustomObject cache. It also refreshes the AksEdge config data if it was read from AksEdgeConfigFile. </details>

<details><summary>Remove-AideDeployment</summary>

Invokes Remove-AksEdgeDeployment to remove the deployment. </details>

<details><summary>Remove-AideMsi</summary>

Checks and removes the installed AksEdge Msi. It also removes the AksEdge module from the active Powershell session, to avoid usage of the cached module after the msi is uninstalled. </details>

<details><summary>Remove-AideVmSwitch</summary>

Removes the external VM Switch on the specified net adapter </details>

<details><summary>Set-AideUserConfig</summary>

Validates and sets the user config PSCustomObject with either jsonFile or jsonString parameter. Either one must be specified. </details>

<details><summary>Start-AideWorkflow</summary>

Runs the end to end workflow for AksEdgeDeploy. Based on the input jsonFile/jsonString, it installs required msi, creates switch and deploys the cluster.This function also enables Hyper-V is it is not enabled and triggers a reboot. The function **doesnot resume** after reboot. </details>

<details><summary>Test-AideArcKubernetes</summary>

This command tests if Arc-enabled Kubernetes is connected. It checks whether the cluster name is present in the list of arc-enabled kubernetes in the given resource group.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Test-AideArcServer</summary>

This command tests if the connected machine agent is installed and connected to Azure Arc-enabled server.The inputs required are consumed from the aide-userconfig.json file. </details>

<details><summary>Test-AideDeployment</summary>

Checks if there is a AksEdge deployment on the machine. It looks for the .vhdx files created for the Linux or Windows VMs. </details>

<details><summary>Test-AideLinuxVmRun</summary>

Tests if the AksEdge Linux VM is running. </details>

<details><summary>Test-AideMsiInstall</summary>

Validates if the requested AksEdge Msi flavour is installed. The Switch -Install when specified will install the Msi if not found.It will also load the AksEdge module into the active PowerShell session. </details>

<details><summary>Test-AideUserConfig</summary>

Validates the user config PSCustomObject for correctness and completeness. Also validates if the required virtual switch is available. </details>

<details><summary>Test-AideVmSwitch</summary>

Tests if the specified VM Switch is available and the associated net adapter is connected. If the -Create flag is specified, it attempts to create a VMMS switch. </details>
