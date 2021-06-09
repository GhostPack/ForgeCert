rule ForgeCert
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
        author = "Will Schroeder (@harmj0y)"
    strings:
        $typelibguid = "bd346689-8ee6-40b3-858b-4ed94f08d40a" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}