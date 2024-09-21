using namespace System.IO
using namespace System.Drawing
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

enum EncryptionScope {
  User    # The encrypted data can be decrypted with the same user on any machine.
  Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

enum Compression {
  Gzip
  Deflate
  ZLib
  # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}
#region    Shuffl3r
# .DESCRIPTION
#     Shuffles bytes, nonce, and other info into a jumbled mess that can be split using a password.
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible.
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
#     The donside is that: Input bytes.length has to be >= 16.
class Shuffl3r {
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
    return [Shuffl3r]::Combine($bytes, $Nonce, [AesGCM]::tostring($Passwod))
  }
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
    if ($bytes.Length -lt ($Nonce.Length + 1)) {
      throw [System.ArgumentOutOfRangeException]::new('$Bytes.length has to be >= $Nonce.Length')
    }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new($Nonce.Length);
    Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
    [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
    for ([int]$i = 0; $i -lt $Indices.Length; $i++) { $combined[$Indices[$i]] = $Nonce[$i] }
    $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -NotIn $Indices };
    foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
    return $combined
  }
  static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
    return [Shuffl3r]::Split($ShuffledBytes, [AesGCM]::tostring($Passwod), [int]$NonceLength);
  }
  static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
    if ($null -eq $ShuffledBytes) { throw [System.ArgumentNullException]::new('$ShuffledBytes') }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [System.ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new([int]$NonceLength);
    Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
    $Nonce = [Byte[]]::new($NonceLength);
    [byte[]]$Bytes = @(); $i = 0; $rem = (0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -NotIn $Indices }
    foreach ($i in $rem) { $bytes += $ShuffledBytes[$i] };
    for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
    return ($bytes, $Nonce)
  }
  static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
    if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [System.ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
    if ([string]::IsNullOrWhiteSpace($randomString)) { throw [System.ArgumentNullException]::new('$randomString') }
    [Byte[]]$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$randomString))
    [int[]]$indices = [int[]]::new($Count)
    for ($i = 0; $i -lt $Count; $i++) {
      [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
      while ($indices -contains $nextIndex) {
        $nextIndex = ($nextIndex + 1) % $HighestIndex
      }
      $indices[$i] = $nextIndex
    }
    return $indices
  }
}
#endregion Shuffl3r

#region    AesGCM
# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $secmessage = [Aesgcm]::Encrypt("Yess this is a S3crEt!", (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#
#     # On recieving PC:
#     $orginalmsg = [AesGcm]::Decrypt($secmessage, (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo $orginalmsg # should be: Yess this is a S3crEt!
class AesGCM {
  static hidden [EncryptionScope] $Scope = [EncryptionScope]::User
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [convert]::ToBase64String([AesGCM]::Encrypt([System.Text.Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
    [System.IntPtr]$th = [System.IntPtr]::new(0);
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = $bytes;
      $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                    # Generate a random IV for each iteration:
                    [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
                    $tag = [byte[]]::new($TAG_SIZE);
                    $Encrypted = [byte[]]::new($_bytes.Length);
                    [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
                    $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
                ) Done"
      }
    } catch {
      if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
        Write-Warning "Wrong password"
      }
      throw $_
    } finally {
      [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    if (![string]::IsNullOrWhiteSpace($Compression)) {
      $_bytes = [AesGCM]::ToCompressed($_bytes, $Compression);
    }
    return $_bytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [System.Text.Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetDerivedSalt($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([System.Security.Cryptography.Rfc2898DeriveBytes]::new([AesGCM]::tostring($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(32)));
    [System.IntPtr]$th = [System.IntPtr]::new(0);
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ToDecompressed($bytes, $Compression) } else { $bytes }
      $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                    # Split the real encrypted bytes from nonce & tags then decrypt them:
                    ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
                    ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
                    $Decrypted = [byte[]]::new($b.Length);
                    $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
                    $_bytes = $Decrypted;
                ) Done"
      }
    } catch {
      if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
        Write-Warning "Wrong password"
      }
      throw $_
    } finally {
      [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    return $_bytes
  }
  static [byte[]] ToCompressed([byte[]]$Bytes) {
    return [AesGCM]::ToCompressed($Bytes, 'Gzip');
  }
  static [string] ToCompressed([string]$Plaintext) {
    return [convert]::ToBase64String([AesGCM]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
  }
  static [byte[]] ToCompressed([byte[]]$Bytes, [string]$Compression) {
    if (("$Compression" -as 'Compression') -isnot 'Compression') {
      Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
    }
    $outstream = [System.IO.MemoryStream]::new()
    $Comstream = switch ($Compression) {
      "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
      "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
      "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
      Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
    }
    [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
    [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
    return $OutPut;
  }
  static [byte[]] ToDeCompressed([byte[]]$Bytes) {
    return [AesGCM]::ToDecompressed($Bytes, 'Gzip');
  }
  static [string] ToDecompressed([string]$Base64Text) {
    return [System.Text.Encoding]::UTF8.GetString([AesGCM]::ToDecompressed([convert]::FromBase64String($Base64Text)));
  }
  static [byte[]] ToDeCompressed([byte[]]$Bytes, [string]$Compression) {
    if (("$Compression" -as 'Compression') -isnot 'Compression') {
      Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
    }
    $inpStream = [System.IO.MemoryStream]::new($Bytes)
    $ComStream = switch ($Compression) {
      "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
      "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
      "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
      Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
    }
    $outStream = [System.IO.MemoryStream]::new();
    [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
    [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
    return $OutPut;
  }
  static [string] ToString([System.Security.SecureString]$SecureString) {
    [string]$Pstr = [string]::Empty;
    [IntPtr]$zero = [IntPtr]::Zero;
    if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
      return [string]::Empty;
    }
    try {
      Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
      Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
    } finally {
      if ($zero -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
      }
    }
    return $Pstr;
  }
  static [SecureString] ToSecurestring([string]$String) {
    $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
    if (![string]::IsNullOrEmpty($String)) {
      $Chars = $String.toCharArray()
      ForEach ($Char in $Chars) {
        $SecureString.AppendChar($Char)
      }
    }
    $SecureString.MakeReadOnly();
    return $SecureString
  }
  # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
  static [string] GetUniqueMachineId() {
    Write-Verbose "Get MachineId ..."
    $Id = [string]($Env:MachineId)
    $vp = (Get-Variable VerbosePreference).Value
    try {
      Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
      $sha256 = [System.Security.Cryptography.SHA256]::Create()
      $HostOS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
      if ($HostOS -eq "Windows") {
        if ([string]::IsNullOrWhiteSpace($Id)) {
          $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
          Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineId))));
        }
        $Id = [string]($Env:MachineId)
      } elseif ($HostOS -eq "Linux") {
        # $Id = (sudo cat /sys/class/dmi/id/product_uuid).Trim() # sudo prompt is a nono
        # Lets use mac addresses
        $Id = ([string[]]$(ip link show | grep "link/ether" | awk '{print $2}') -join '-').Trim()
        $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
      } elseif ($HostOS -eq "macOS") {
        $Id = (system_profiler SPHardwareDataType | Select-String "UUID").Line.Split(":")[1].Trim()
        $Id = [convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Id)))
      } else {
        throw "Error: HostOS = '$HostOS'. Could not determine the operating system."
      }
    } catch {
      throw $_
    } finally {
      $sha256.Clear(); $sha256.Dispose()
      Set-Variable VerbosePreference -Value $vp
    }
    return $Id
  }
  static [byte[]] GetDerivedSalt([securestring]$password) {
    $rfc2898 = $null; $s4lt = $null; [byte[]]$s6lt = if ([AesGCM]::Scope.ToString() -eq "Machine") {
      [System.Text.Encoding]::UTF8.GetBytes([AesGcm]::GetUniqueMachineId())
    } else {
      [convert]::FromBase64String("qmkmopealodukpvdiexiianpnnutirid")
    }
    Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $password;
    Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $s6lt;
    Set-Variable -Name rfc2898 -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $s6lt));
    Set-Variable -Name s4lt -Scope Local -Visibility Private -Option Private -Value $($rfc2898.GetBytes(16));
    return $s4lt
  }
}
#endregion AesGCM
