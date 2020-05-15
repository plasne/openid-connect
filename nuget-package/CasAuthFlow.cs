namespace CasAuth
{

    public class CasAuthFlow
    {
        public string idp { get; set; }
        public string redirecturi { get; set; }
        public string state { get; set; }
        public string nonce { get; set; }
    }

}

