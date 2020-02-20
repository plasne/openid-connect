using System.Linq;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CasAuth.Test
{

    public class CasConfigTest
    {

        [Fact]
        public async void GetString()
        {

            // create test environment
            var config = new CasConfig();
            System.Environment.SetEnvironmentVariable("MY_KEY_af3d", "my-set-value");

            // ensure if key is not set, the default is taken
            var v0 = CasConfig.GetStringOnce("MY_KEY_vcr1", dflt: "my-default");
            Assert.Equal("my-default", v0);

            // ensure if key is set, that value is used
            var v1 = CasConfig.GetStringOnce("MY_KEY_af3d", dflt: "my-default");
            Assert.Equal("my-set-value", v1);

            // ensure if key is not set, the default is taken from cached
            var v2 = await config.GetString("MY_KEY_vcr1", val: null, dflt: "my-default");
            Assert.Equal("my-default", v2);

            // ensure the original default is used when a 2nd cached call is made
            var v3 = await config.GetString("MY_KEY_vcr1", val: null, dflt: "my-second-default");
            Assert.Equal("my-default", v3);

            // ensure the original default is used when a 2nd cached call is made, even if a new value is provided
            var v4 = await config.GetString("MY_KEY_vcr1", val: "my-runtime-value", dflt: "my-second-default");
            Assert.Equal("my-default", v4);

            // ensure if a runtime value is provided, it supercedes the environment variable
            var v5 = await config.GetString("MY_KEY_af3d", val: "my-runtime-value", dflt: "my-default");
            Assert.Equal("my-runtime-value", v5);

        }

        [Fact]
        public async void GetInt()
        {

            // create test environment
            var config = new CasConfig();
            System.Environment.SetEnvironmentVariable("MY_KEY_x21d", "10");
            System.Environment.SetEnvironmentVariable("MY_KEY_yt42", "not-an-int");

            // ensure if key is not set, the default is taken
            var v0 = CasConfig.GetIntOnce("MY_KEY_irr2", dflt: -1);
            Assert.Equal(-1, v0);

            // ensure if key is set, that value is used
            var v1 = CasConfig.GetIntOnce("MY_KEY_x21d", dflt: -1);
            Assert.Equal(10, v1);

            // ensure if key is not set, the default is taken from cached
            var v2 = await config.GetInt("MY_KEY_irr2", val: null, dflt: -1);
            Assert.Equal(-1, v2);

            // ensure the original default is used when a 2nd cached call is made
            var v3 = await config.GetInt("MY_KEY_irr2", val: null, dflt: -2);
            Assert.Equal(-1, v3);

            // ensure the original default is used when a 2nd cached call is made, even if a new value is provided
            var v4 = await config.GetInt("MY_KEY_irr2", val: "20", dflt: -2);
            Assert.Equal(-1, v4);

            // ensure if a runtime value is provided, it supercedes the environment variable
            var v5 = await config.GetInt("MY_KEY_x21d", val: "20", dflt: -1);
            Assert.Equal(20, v5);

            // ensure a runtime value is an integer or ignored
            var v6 = await config.GetInt("MY_KEY_xx12", val: "not-an-int", dflt: -1);
            Assert.Equal(-1, v6);

            // ensure an env value is an integer or ignored
            var v7 = await config.GetInt("MY_KEY_yt42", val: null, dflt: -1);
            Assert.Equal(-1, v7);

        }

        [Fact]
        public async void GetBool()
        {

            // create test environment
            var config = new CasConfig();
            System.Environment.SetEnvironmentVariable("MY_KEY_zzew", "tRuE");
            System.Environment.SetEnvironmentVariable("MY_KEY_1i23", "1");
            System.Environment.SetEnvironmentVariable("MY_KEY_fmfu", "YES");
            System.Environment.SetEnvironmentVariable("MY_KEY_i444", "falSE");
            System.Environment.SetEnvironmentVariable("MY_KEY_3jej", "0");
            System.Environment.SetEnvironmentVariable("MY_KEY_49f3", "No");

            // ensure if key is not set, the default is taken
            var v0 = CasConfig.GetBoolOnce("MY_KEY_aqws", dflt: true);
            Assert.True(v0);

            // ensure if key is set, that value is used
            var v1 = CasConfig.GetBoolOnce("MY_KEY_zzew", dflt: false);
            Assert.True(v1);

            // ensure if key is not set, the default is taken from cached
            var v2 = await config.GetBool("MY_KEY_wfef", val: null, dflt: true);
            Assert.True(v2);

            // ensure the original default is used when a 2nd cached call is made
            var v3 = await config.GetBool("MY_KEY_wfef", val: null, dflt: false);
            Assert.True(v3);

            // ensure the original default is used when a 2nd cached call is made, even if a new value is provided
            var v4 = await config.GetBool("MY_KEY_wfef", val: "false", dflt: false);
            Assert.True(v4);

            // ensure if a runtime value is provided, it supercedes the environment variable
            var v5 = await config.GetBool("MY_KEY_zzew", val: "false", dflt: true);
            Assert.False(v5);

            // ensure different TRUE conditions are all true
            var v6 = CasConfig.GetBoolOnce("MY_KEY_zzew", dflt: false);
            Assert.True(v6);
            var v7 = CasConfig.GetBoolOnce("MY_KEY_1i23", dflt: false);
            Assert.True(v7);
            var v8 = CasConfig.GetBoolOnce("MY_KEY_fmfu", dflt: false);
            Assert.True(v8);

            // ensure different FALSE conditions are all false
            var v9 = CasConfig.GetBoolOnce("MY_KEY_i444", dflt: true);
            Assert.False(v9);
            var v10 = CasConfig.GetBoolOnce("MY_KEY_3jej", dflt: true);
            Assert.False(v10);
            var v11 = CasConfig.GetBoolOnce("MY_KEY_49f3", dflt: true);
            Assert.False(v11);

        }

        [Fact]
        public async void GetArray()
        {

            // create test environment
            var config = new CasConfig();
            System.Environment.SetEnvironmentVariable("MY_KEY_djeu", "blue, green, yellow");
            System.Environment.SetEnvironmentVariable("MY_KEY_i2if", "");
            System.Environment.SetEnvironmentVariable("MY_KEY_3k32", "pink");
            System.Environment.SetEnvironmentVariable("MY_KEY_4k4j", "red,orange");
            System.Environment.SetEnvironmentVariable("MY_KEY_i442", "purple;green");

            // ensure if key is not set, the default is taken
            var v0 = CasConfig.GetArrayOnce("MY_KEY_93i3", dflt: new string[] { "yes", "no" });
            Assert.Equal(2, v0.Count());
            Assert.Equal("yes", v0[0]);
            Assert.Equal("no", v0[1]);

            // ensure if key is set, that value is used
            var v1 = CasConfig.GetArrayOnce("MY_KEY_djeu");
            Assert.Equal(3, v1.Count());
            Assert.Equal("blue", v1[0]);
            Assert.Equal("green", v1[1]);
            Assert.Equal("yellow", v1[2]);

            // ensure if key is not set, the default is taken from cached
            var v2 = await config.GetArray("MY_KEY_93i3", val: null, dflt: new string[] { "cat", "dog" });
            Assert.Equal(2, v2.Count());
            Assert.Equal("cat", v2[0]);
            Assert.Equal("dog", v2[1]);

            // ensure the original default is used when a 2nd cached call is made
            var v3 = await config.GetArray("MY_KEY_93i3", val: null, dflt: new string[] { "yes", "no" });
            Assert.Equal(2, v3.Count());
            Assert.Equal("cat", v3[0]);
            Assert.Equal("dog", v3[1]);

            // ensure the original default is used when a 2nd cached call is made, even if a new value is provided
            var v4 = await config.GetArray("MY_KEY_93i3", val: "yes, no", dflt: new string[] { "yes", "no" });
            Assert.Equal(2, v4.Count());
            Assert.Equal("cat", v4[0]);
            Assert.Equal("dog", v4[1]);

            // ensure if a runtime value is provided, it supercedes the environment variable
            var v5 = await config.GetArray("MY_KEY_3i32", val: "brick, wood");
            Assert.Equal(2, v5.Count());
            Assert.Equal("brick", v5[0]);
            Assert.Equal("wood", v5[1]);

            // ensure empty is processed correctly
            var v6 = await config.GetArray("MY_KEY_i2if", val: null);
            Assert.Empty(v6);

            // ensure a single is processed correctly
            var v7 = await config.GetArray("MY_KEY_3k32", val: null);
            Assert.Single(v7);
            Assert.Equal("pink", v7[0]);

            // ensure no spaces is processed correctly
            var v8 = await config.GetArray("MY_KEY_4k4j", val: null);
            Assert.Equal(2, v8.Count());
            Assert.Equal("red", v8[0]);
            Assert.Equal("orange", v8[1]);

            // ensure semi-colon is processed correctly
            var v9 = await config.GetArray("MY_KEY_i442", val: null, delimiter: ";");
            Assert.Equal(2, v9.Count());
            Assert.Equal("purple", v9[0]);
            Assert.Equal("green", v9[1]);

        }

        [Fact]
        public async void GetEnum()
        {

            // create test environment
            var config = new CasConfig();
            System.Environment.SetEnvironmentVariable("MY_KEY_3k3k", "strict");

            // ensure if key is not set, the default is taken
            var v0 = CasConfig.GetEnumOnce<SameSiteMode>("MY_KEY_4j4j", dflt: SameSiteMode.None);
            Assert.Equal(SameSiteMode.None, v0);

            // ensure if key is set, that value is used
            var v1 = CasConfig.GetEnumOnce<SameSiteMode>("MY_KEY_3k3k", dflt: SameSiteMode.None);
            Assert.Equal(SameSiteMode.Strict, v1);

            // ensure if key is not set, the default is taken from cached
            var v2 = await config.GetEnum<SameSiteMode>("MY_KEY_4j4j", val: null, dflt: SameSiteMode.None);
            Assert.Equal(SameSiteMode.None, v2);

            // ensure the original default is used when a 2nd cached call is made
            var v3 = await config.GetEnum<SameSiteMode>("MY_KEY_4j4j", val: null, dflt: SameSiteMode.Lax);
            Assert.Equal(SameSiteMode.None, v3);

            // ensure the original default is used when a 2nd cached call is made, even if a new value is provided
            var v4 = await config.GetEnum<SameSiteMode>("MY_KEY_4j4j", val: "strict", dflt: SameSiteMode.Lax);
            Assert.Equal(SameSiteMode.None, v4);

            // ensure if a runtime value is provided, it supercedes the environment variable
            var v5 = await config.GetEnum<SameSiteMode>("MY_KEY_3k3k", val: "strict", dflt: SameSiteMode.Lax);
            Assert.Equal(SameSiteMode.Strict, v5);

        }



    }

}