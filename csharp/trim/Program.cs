// Names exactly one plugin. If the trimmer keeps the AWS signing code
// anyway, the split buys a consumer nothing in .NET and check-trim says so.
using Voxgig.Sekreto.Plugins;

public static class Program
{
    public static void Main()
    {
        System.Console.WriteLine(Hashicorp.Plugin.Name);
    }
}
