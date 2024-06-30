using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

// Non-DI aware scenarios for Data Protection in ASP.NET Core
// https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/non-di-scenarios?view=aspnetcore-8.0
{
    var destFolder = Path.Combine(System.Environment.GetEnvironmentVariable("TMPDIR") ?? AppDomain.CurrentDomain.BaseDirectory, "myapp_keys");

    // var dataProtectionProvider = DataProtectionProvider.Create(new DirectoryInfo(destFolder));

    var dataProtectionProvider = DataProtectionProvider.Create(new DirectoryInfo(destFolder), configuration =>
        {
            configuration.SetApplicationName("my-app");
            // configuration.ProtectKeysWithDpapi();
        }
    );

    var protector = dataProtectionProvider.CreateProtector("Program.No-DI");
        
    var protectedPayload = protector.Protect("emre-mumcu");
    
    var unprotectedPayload = protector.Unprotect(protectedPayload);

    Console.WriteLine("Non-DI");
    Console.WriteLine($"{unprotectedPayload}");
    Console.WriteLine($"{protectedPayload}");
}


// DI aware scenarios for Data Protection in ASP.NET Core
{
    var serviceCollection = new ServiceCollection();
    serviceCollection.AddDataProtection();
    var services = serviceCollection.BuildServiceProvider();

    var instance = ActivatorUtilities.CreateInstance<MyClass>(services);

    var encrypted = instance.Encrypt("emre-mumcu");
    var decrypted = instance.Decrypt(encrypted);

    Console.WriteLine("DI");
    Console.WriteLine(decrypted);
    Console.WriteLine(encrypted);
}

public class MyClass
{
    IDataProtector _protector;

    public MyClass(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("Program.No-DI");
    }

    public string Encrypt(string input)
    {
        return _protector.Protect(input);
    }

    public string Decrypt(string input)
    {
        return _protector.Unprotect(input);
    }
}