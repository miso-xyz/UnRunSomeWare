Imports dnlib.DotNet
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Module Module1

    Sub Main(ByVal args() As String)
        Console.Title = "UnRunSomeAware v1.0"
        Dim rng As New Random
        Dim splitName = rng.Next()
        Dim patchedApp As ModuleDefMD = ModuleDefMD.Load(args(0))
        Dim strings As New List(Of String)
        Dim isInExtensionTargetArray As Boolean = False
        Dim ransomMode As Boolean = True
        Console.WriteLine("UnRunSomeAware v1.0 - by misonothx (https://github.com/miso-xyz)")
        Console.WriteLine()
        Console.WriteLine("Scanning """ & args(0) & """...")
        Console.WriteLine()
        For x = 0 To patchedApp.Types.Count - 1
            If patchedApp.Types(x).Name.ToString = "RunSomeAware" Then
                For x2 = 0 To patchedApp.Types(x).Methods.Count - 1
                    If patchedApp.Types(x).Methods(x2).Name.ToString().Split("::")(0) = ".cctor" Then
                        For x3 = 0 To patchedApp.Types(x).Methods(x2).Body.Instructions.Count - 1
                            If patchedApp.Types(x).Methods(x2).Body.Instructions(x3).OpCode.ToString = "ldstr" Then
                                If isInExtensionTargetArray Then
                                    strings.Add(splitName)
                                    isInExtensionTargetArray = False
                                End If
                                strings.Add(patchedApp.Types(x).Methods(x2).Body.Instructions(x3).Operand.ToString())
                            ElseIf patchedApp.Types(x).Methods(x2).Body.Instructions(x3).OpCode.ToString = "newarr" AndAlso Not strings.Contains(splitName) Then
                                isInExtensionTargetArray = True
                            ElseIf patchedApp.Types(x).Methods(x2).Body.Instructions(x3).OpCode.ToString = "ldsfld" AndAlso strings.Contains(splitName) Then
                                If patchedApp.Types(x).Methods(x2).Body.Instructions(x3).Operand.ToString.Split("::")(2) = "CrypterExt" Then
                                    strings.Add(strings(1))
                                End If
                            ElseIf patchedApp.Types(x).Methods(x2).Body.Instructions(x3).OpCode.ToString = "stsfld" AndAlso patchedApp.Types(x).Methods(x2).Body.Instructions(x3).Operand.ToString.Contains("Mode") Then
                                ransomMode = CBool(patchedApp.Types(x).Methods(x2).Body.Instructions(x3 - 1).OpCode.ToString.Replace("ldc.i4.", Nothing))
                            End If
                        Next
                    End If
                Next
            End If
        Next
        Console.ForegroundColor = ConsoleColor.Magenta
        Console.WriteLine("Encryption Key: " & strings(0))
        Console.WriteLine()
        Console.ForegroundColor = ConsoleColor.Yellow
        Console.WriteLine("Encrypted Extension: " & strings(1))
        Console.WriteLine("Directory Target: " & strings(2))
        Console.WriteLine("Mode: " & If(ransomMode, "Encryption", "Decryption"))
        Console.WriteLine()
        Console.ForegroundColor = ConsoleColor.Green
        Console.WriteLine("Affected Extensions: " & (strings.Count - strings.IndexOf(splitName)) - 1)
        Console.WriteLine("{")
        For x = 1 To (strings.Count - 1) - (strings.IndexOf(splitName))
            Console.WriteLine(vbTab & strings((strings.IndexOf(splitName)) + x))
        Next
        Console.WriteLine("}")
        Console.ReadKey()
    End Sub


    Function Decrypt(ByVal path As String, ByVal key As String) As Integer
        Dim fs As New FileStream(path, FileMode.Create)
        Using rijndael As Rijndael = New RijndaelManaged()
            rijndael.Key = New SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(key))
            rijndael.Mode = CipherMode.ECB
            Using cryptoStream As CryptoStream = New CryptoStream(fs, rijndael.CreateDecryptor(), CryptoStreamMode.Write)
                Dim array As Byte() = New Byte(fs.Length - 1) {}
                While fs.Read(array, 0, array.Length) > 0
                    cryptoStream.Write(array, 0, array.Length)
                End While
            End Using
        End Using
    End Function


End Module