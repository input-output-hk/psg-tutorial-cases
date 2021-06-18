import io.iohk.atala.prism.kotlin.protos.*
import kotlinx.coroutines.runBlocking

object BlockingCalls {
    fun registerDID(connector: ConnectorService.Client, request: RegisterDIDRequest): RegisterDIDResponse{
        return runBlocking { connector.RegisterDID(request) }
    }

    fun generateConnectionTokenAuth(connector:ConnectorService.Client, request: GenerateConnectionTokenRequest, metadata: PrismMetadata): GenerateConnectionTokenResponse{
        return runBlocking { connector.GenerateConnectionTokenAuth(request,metadata) }
    }

    fun getConnectionTokenInfo(connector: ConnectorService.Client, request: GetConnectionTokenInfoRequest): GetConnectionTokenInfoResponse{
        return runBlocking { connector.GetConnectionTokenInfo(request) }
    }

    fun addConnectionFromTokenAuth(connector: ConnectorService.Client, request: AddConnectionFromTokenRequest, metadata:PrismMetadata): AddConnectionFromTokenResponse{
        return runBlocking { connector.AddConnectionFromTokenAuth(request,metadata) }
    }

    fun issueCredentialBatch(connector: NodeService.Client, request: IssueCredentialBatchRequest): IssueCredentialBatchResponse{
        return runBlocking { connector.IssueCredentialBatch(request) }
    }

    fun getConnectionByTokenAuth(connector: ConnectorService.Client, request: GetConnectionByTokenRequest,metadata: PrismMetadata): GetConnectionByTokenResponse{
        return runBlocking { connector.GetConnectionByTokenAuth(request,metadata) }
    }

    fun sendMessageAuth(connector: ConnectorService.Client, request: SendMessageRequest,metadata: PrismMetadata): SendMessageResponse{
        return runBlocking { connector.SendMessageAuth(request,metadata) }
    }

    fun getMessagesPaginatedAuth(connector: ConnectorService.Client, request: GetMessagesPaginatedRequest,metadata: PrismMetadata): GetMessagesPaginatedResponse{
        return runBlocking { connector.GetMessagesPaginatedAuth(request,metadata) }
    }

    fun getDidDocument(connector: NodeService.Client, request: GetDidDocumentRequest): GetDidDocumentResponse{
        return runBlocking { connector.GetDidDocument(request) }
    }

    fun getCredentialRevocationTime(connector: NodeService.Client, request: GetCredentialRevocationTimeRequest): GetCredentialRevocationTimeResponse{
        return runBlocking { connector.GetCredentialRevocationTime(request) }
    }

    fun revokeCredentials(connector: NodeService.Client, request: RevokeCredentialsRequest): RevokeCredentialsResponse{
        return runBlocking { connector.RevokeCredentials(request) }
    }
}