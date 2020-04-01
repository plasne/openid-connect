using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // System.Text.Json was not deserializing properly

namespace CasAuth
{

    public interface ICasConfig
    {

        Dictionary<string, object> Cache { get; }

        Task<Dictionary<string, string>> Load(string[] filters, bool useFullyQualifiedName = false);

        Task Apply(string[] filters = null);

        Task<string> GetString(string key, string val = null, string dflt = null);

        Task<int> GetInt(string key, string val = null, int dflt = 0);

        Task<bool> GetBool(string key, string val = null, bool dflt = false);

        Task<string[]> GetArray(string key, string val = null, string delimiter = ",", string[] dflt = null);

        Task<T> GetEnum<T>(string key, string val = null, T dflt = default(T)) where T : struct;

        void Require(string key, string value, bool hideValue = false);

        void Require(string key, string[] values, bool hideValue = false);

        void Require(string key, bool hideValue = false);

        bool Optional(string key, string value, bool hideValue = false, bool hideIfEmpty = false);

        bool Optional(string key, string[] values, bool hideValue = false, bool hideIfEmpty = false);

        bool Optional(string key, bool value, bool hideValue = false, bool hideIfEmpty = false);

        bool Optional(string key, bool hideValue = false, bool hideIfEmpty = false);

    }


}

