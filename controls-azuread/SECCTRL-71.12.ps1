function Invoke-Control {
    param()

    $complianceStatus = [ComplianceStatus]::new()
    $complianceStatus.ControlTitle = "SECCTRL-71.12 AKS Volumes should use encryption with BYOK if required"
    $complianceStatus.CustomCompliance = "ccm3.0.1"
    $complianceStatus.CustomComplianceRef = "ccm3.0.1:tdccm-ekm-002"
    $complianceStatus.Version = "1.0.2"
    $complianceStatus.Priority = "Medium"
    
    Write-ControlLog  "Name: $controlTitle"
    Write-ControlLog  "Description: $controlTitle"

    $controlSettings = Get-ControlSettings
    $dataClassificationTagName = $controlSettings.dataClassificationTagName
    $dataClassificationTagValues = $controlSettings.dataClassificationTagValues
    $keyVaultNamePattern = $controlSettings.keyVaultNamePattern

    Write-ControlLog "checking kubectl version..."
    kubectl version --client

    $aksResources = az aks list | ConvertFrom-Json
    foreach ($aksResource in $aksResources) {
        $aksName = $aksResource.name
        $resourceGroupName = $aksResource.resourceGroup
        $resourceId = $aksResource.id
        Write-ControlLog "Checking Encryption for following AKS: $aksName; resourceGroupName: $resourceGroupName"

        $complianceStatus.ResourceGroup = "$resourceGroupName"
        $complianceStatus.ResourceType = "Kubernetes"
        $complianceStatus.ResourceName = "$aksName"
        $complianceStatus.ResourceId = "$resourceId"

        $dataClassificationTag = $aksResource.tags.$dataClassificationTagName
        if ($null -ne $dataClassificationTag -and $dataClassificationTag -notIn $dataClassificationTagValues) {
            $complianceStatus.Result = "Compliant"
            $complianceStatus.Comment = "AKS data classification tag not in list of tag values"
            Add-Report $complianceStatus
            continue
        }

        try {
            az aks get-credentials --resource-group $resourceGroupName --name $aksName --overwrite-existing
            Write-ControlLog "credentials received, kubelogin..."
            kubelogin convert-kubeconfig -l msi
            Write-ControlLog "kubelogin completed"

            if((kubectl auth can-i get storageclass) -ne "yes"){
                $complianceStatus.Result = "Error"
                $complianceStatus.Comment = "Insufficient privileges, runner does not allowed to access aks"
                Add-Report $complianceStatus
                continue
            }

            $storageClasses = (kubectl get storageclass -o json) | ConvertFrom-Json
            Write-ControlLog "storageclass has been received, storageClasses.items.count $($storageClasses.items.count)"
            if($null -eq $storageClasses.items -or $storageClasses.items.count -eq 0){
                $complianceStatus.Result = "Error"
                $complianceStatus.Comment = "Expected results are not returned by the cluster, review privileges, runner may not allowed to access aks"
                Add-Report $complianceStatus
                continue
            }

            $flag = $false
            foreach ($storageClass in $storageClasses.items) {
                $parameters = $storageClass.parameters
                if ($null -ne $parameters.diskEncryptionSetID -and $parameters.diskEncryptionSetID -ne "") {
                    $diskEncryptionSet = az disk-encryption-set show --ids "$($parameters.diskEncryptionSetID)" | ConvertFrom-Json
                    if ($diskEncryptionSet.activeKey.sourceVault.id -match $keyVaultNamePattern) {
                        $flag = $true
                        break
                    }
                }
            }
        } catch {
            $complianceStatus.Result = "Error"
            $complianceStatus.Comment = "Error Occured $($_.Exception)"
            Add-Report $complianceStatus
            continue
        }

        if ($flag) {
            $complianceStatus.Result = "Compliant"
            $complianceStatus.Comment = "Data Disk Encryption is enabled at AKS"
            Add-Report $complianceStatus
        }
        else {
            $complianceStatus.Result = "NonCompliant"
            $complianceStatus.Comment = "Data Disk Encryption is disabled at AKS"
            Add-Report $complianceStatus
        }
    }
}

Invoke-Control
