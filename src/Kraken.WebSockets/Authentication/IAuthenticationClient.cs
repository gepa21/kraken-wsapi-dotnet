using System.Threading.Tasks;

namespace Kraken.WebSockets.Authentication
{
    public interface IAuthenticationClient
    {
        Task<AuthToken> GetWebsocketToken();

        Task<T> InvokePrivateApi<T>(string apiName, params (string key, string value)[] parameters);
    }
}
