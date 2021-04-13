using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kraken.WebSockets.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class AuthenticationClient : IAuthenticationClient
    {
        private readonly string uri;
        private readonly SecureString apiKey;
        private readonly SecureString apiSecret;
        private readonly int version;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationClient" /> class.
        /// </summary>
        /// <param name="uri">The URI.</param>
        /// <param name="apiKey">The API key.</param>
        /// <param name="apiSecret">The API secret.</param>
        /// <param name="version">The version. Default Value = 0</param>
        public AuthenticationClient(string uri, SecureString apiKey, SecureString apiSecret, int version = 0)
        {
            this.uri = uri;
            this.apiKey = apiKey;
            this.apiSecret = apiSecret;
            this.version = version;
        }

        /// <summary>
        /// Requests the websocket token from the configured REST API endpoint
        /// </summary>
        /// <returns></returns>
        public Task<AuthToken> GetWebsocketToken() => InvokePrivateApi<AuthToken>("GetWebSocketsToken");

        /// <summary>
        /// Perform request to the private REST API endpoint
        /// </summary>
        /// <returns></returns>
        public async Task<T> InvokePrivateApi<T>(string apiName, params (string key, string value)[] parameters)
        {
            var formContent = new Dictionary<string, string>();

            // generate a 64 bit nonce using a timestamp at tick resolution
            var nonce = DateTime.UtcNow.Ticks;
            formContent.Add("nonce", nonce.ToString());

            if (parameters != null)
                foreach (var p in parameters)
                    formContent[p.key] = p.value;

            var path = $"/{version}/private/{apiName}";
            var address = $"{uri}{path}";

            var content = new FormUrlEncodedContent(formContent);
            var request = new HttpRequestMessage(HttpMethod.Post, address)
            {
                Content = content,
                Headers =
                {
                    {"API-Key", apiKey.ToPlainString()},
                    {"API-Sign", Convert.ToBase64String(CalculateSignature(await content.ReadAsByteArrayAsync(), nonce, path)) }
                }
            };

            using (var httpClient = new HttpClient())
            {
                var response = await httpClient.SendAsync(request);
                using (var stream = await response.Content.ReadAsStreamAsync())
                {
                    using (var jsonReader = new JsonTextReader(new StreamReader(stream)))
                    {
                        var jObject = new JsonSerializer().Deserialize<JObject>(jsonReader);
                        return jObject.Property("result").Value.ToObject<T>();
                    }
                }
            }
        }

        private byte[] CalculateSignature(byte[] props, long nonce, string path)
        {
            var decodedSecret = Convert.FromBase64String(apiSecret.ToPlainString());

            var np = Encoding.UTF8.GetBytes((nonce + Convert.ToChar(0)).ToString()).Concat(props).ToArray();
            var hash256Bytes = SHA256Hash(np);

            var pathBytes = Encoding.UTF8.GetBytes(path);

            var z = pathBytes.Concat(hash256Bytes).ToArray();

            var signature = getHash(decodedSecret, z);

            return signature;
        }

        private byte[] SHA256Hash(byte[] value)
        {
            using (var hash = SHA256.Create())
            {
                return hash.ComputeHash(value);
            }
        }

        private byte[] getHash(byte[] keyByte, byte[] messageBytes)
        {
            using (var hmacsha512 = new HMACSHA512(keyByte))
            {
                var result = hmacsha512.ComputeHash(messageBytes);
                return result;
            }
        }
    }
}
