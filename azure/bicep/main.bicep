// Azure Functions + Blob for SatScan ingestion
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'satscanlogs${uniqueString(resourceGroup().id)}'
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
}
