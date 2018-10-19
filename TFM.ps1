<#
.SYNOPSIS
  <TFM Homomorphic Encryption Proof of Concept.>
.DESCRIPTION
  <It uses logarithms and powers within this script with
  a Private Key and Microsoft Azure as Cloud database provider.>
.INPUTS
  < By Logarithm definition you can't insert values < 1, because it result < 0 (negative number)
  Logarithm properties:
    - Logk b = x; k^x = b
    - Logk (1) = 0
    - Logk (k) = 1
    - Logk (a*b) = Logk (a) + Logk (b)
    - Logk (a/b) = Logk (a) - Logk (b)
    - Logk (a)^n = n * Logk (a)
    - Logk (x) = Logb (x) / Logb (k)
  >
.OUTPUTS
  <Run the HE operation and get the decrypted result.>
.NOTES
  Version:        1.0
  Author:         <Jose Luis Carrillo Aguilar>
  Relase Date:    <14/10/2018>
  Purpose:        TFM UEM
  
.EXAMPLE
  <The main script is a demo using all functions in this script.>
#>

##### Params #####
param(
        [Parameter(Mandatory=$True)]
        [string]$SQLServerFQDN,
        [Parameter(Mandatory=$True)]
        [string]$Database
)

##### External Modules #####
Import-Module SqlServer

##### Const Vars #####
$ErrorActionPreference = "SilentlyContinue"

##### Functions #####
function Confidential {
    param(
        [Parameter(Mandatory=$True)]
        [string]$Info
    )
    switch($Info){
        "Passphrase"{$Path = ".\Confidential1.txt"}
        "UserSQL"{$Path = ".\Confidential2.txt"}
    }
    $CheckPath = Test-Path -Path $Path
    if($Info -eq "PasswordSQL"){
        $CheckPath = $true
    }
    if($CheckPath){
        if($Info -eq "PasswordSQL"){
            Write-Host "Escriba:"$Info -ForegroundColor Red
            $PwdSQL = Read-Host -AsSecureString | ConvertFrom-SecureString
            
            $SecurePassword = ConvertTo-SecureString -String $PwdSQL
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }else{
            $SecurePassword = ConvertTo-SecureString -String (Get-Content -Path $Path)
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
    }else{
        Write-Host "Escriba:"$Info -ForegroundColor Red
        Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File $Path
        $SecurePassword = ConvertTo-SecureString -String (Get-Content -Path $Path)
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }
    return $Password
}
function sqlcmd {
    param(
        [Parameter(Mandatory=$True)]
        [string]$query
    )
    $ConnectionString = "Server=$SQLServerFQDN;Database=$Database;Integrated Security=False;User ID=$UserSQL;Password=$PasswordSQL;"
    Invoke-Sqlcmd -ConnectionString $ConnectionString -Query $query
}

function CryptoHEL{
    param(
        [Parameter(Mandatory = $true,Position=1)][String] $Passphrase,
        [Parameter(Mandatory = $false,Position=2)][switch] $Encrypt,
        [Parameter(Mandatory = $false,Position=3)][decimal] $Value,
        [Parameter(Mandatory = $false,Position=4)][switch] $PrivateKey
    )
    $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    $utf8 = new-object -TypeName System.Text.UTF8Encoding
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($Passphrase)))
    $md5 = $hash -replace '[-]',""
    #Write-Host El MD5 es: $md5
    $hash = $md5.Remove(2)
    #Write-Host El MD5 Trimmed es: $hash
    $decimal = [Convert]::ToInt64($hash,16)
    #Write-Host La clave privada del usuario es: $decimal
    if($Encrypt){
        $res = ([math]::log($Value)/[math]::log($decimal))
    }elseif($PrivateKey){
        $res = $decimal
    }elseif(!$Encrypt){
        $tempres = [math]::Pow($decimal,$Value)
        $res = [math]::Round($tempres,3)
    }
    return $res
}
function InsertNIF {
    param(
        [Parameter(Mandatory=$True)]
        [decimal]$NIF
    )
    $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $NIF
    sqlcmd "INSERT INTO dbo.NIF (NIF) VALUES ($DNICrypt);"
    Write-Host "NIF: $NIF cifrado en: $DNICrypt insertado"
}

function InsertStandards{
    param(
        [Parameter(Mandatory=$True)]
        [int]$Nota,
        [Parameter(Mandatory=$True)]
        [int]$LeucocitosInfValue,
        [Parameter(Mandatory=$True)]
        [int]$LeucocitosSupValue,
        [Parameter(Mandatory=$True)]
        [decimal]$CocienteCOLValue
    )

    $NotaCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Nota
    $LeucocitosInfValueCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $LeucocitosInfValue
    $LeucocitosSupValueCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $LeucocitosSupValue
    $CocienteCOLValueCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $CocienteCOLValue

    sqlcmd "INSERT INTO dbo.Standards (Standard, Value) VALUES ('Nota',$NotaCrypt);"
    sqlcmd "INSERT INTO dbo.Standards (Standard, Value) VALUES ('LeucocitosInfValue',$LeucocitosInfValueCrypt);"
    sqlcmd "INSERT INTO dbo.Standards (Standard, Value) VALUES ('LeucocitosSupValue',$LeucocitosSupValueCrypt);"
    sqlcmd "INSERT INTO dbo.Standards (Standard, Value) VALUES ('CocienteCOLValue',$CocienteCOLValueCrypt);"

    Write-Host "Todos los valores Standards insertados."
}

function InsertAnalisis{
    param(
        [Parameter(Mandatory=$True)]
        [decimal]$NIF,
        [Parameter(Mandatory=$True)]
        [int]$NumAnalisis,
        [Parameter(Mandatory=$True)]
        [decimal]$Linfocitos,
        [Parameter(Mandatory=$True)]
        [decimal]$Monocitos,
        [Parameter(Mandatory=$True)]
        [decimal]$Colesterol,
        [Parameter(Mandatory=$True)]
        [decimal]$HDL
    )
    $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $NIF
    $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF

    $NumAnalisisCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $NumAnalisis
    $Linfocitos = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Linfocitos
    $Monocitos = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Monocitos
    $Colesterol = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Colesterol
    $HDL = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $HDL
    
    sqlcmd "INSERT INTO dbo.Analisis (IdNIF, NumAnalisis, Linfocitos, Monocitos, Colesterol, HDL) VALUES ($IdNIF, $NumAnalisisCrypt, $Linfocitos, $Monocitos, $Colesterol, $HDL);"
    Write-Host "Analisis $NumAnalisis del paciente con NIF:$NIF cifrado $DNICrypt insertado."
}

function CalcResultadosAnalisis{
    param(
        [Parameter(Mandatory=$True)]
        [decimal[]]$NIFs
    )
    $PrivateKey = CryptoHEL -Passphrase $Passphrase -PrivateKey

    $NIFs | ForEach-Object {
        $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $_
        $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF
        
        $LinfocitosCrypt = (sqlcmd "SELECT * FROM dbo.Analisis WHERE IdNIF = $IdNIF;").Linfocitos
        $MonocitosCrypt = (sqlcmd "SELECT * FROM dbo.Analisis WHERE IdNIF = $IdNIF;").Monocitos
        $ColesterolCrypt = (sqlcmd "SELECT * FROM dbo.Analisis WHERE IdNIF = $IdNIF;").Colesterol
        $HDLCrypt = (sqlcmd "SELECT * FROM dbo.Analisis WHERE IdNIF = $IdNIF;").HDL

        #Logarithm property
        $query1 = "DECLARE @m float;
                   SET @m = (SELECT(ROUND((POWER(CAST($PrivateKey AS float),$LinfocitosCrypt)) + (POWER(CAST($PrivateKey AS float),$MonocitosCrypt)),3)));
                   UPDATE dbo.Analisis SET Leucocitos = LOG(@m,CAST($PrivateKey AS float)) WHERE IdNIF = $IdNIF;"
        
        sqlcmd ($query1)

        $query2 = "DECLARE @m float;
                  SET @m = (SELECT(ROUND(POWER(CAST($PrivateKey AS float),($ColesterolCrypt - $HDLCrypt)),3)));
                  UPDATE dbo.Analisis SET CocienteCOL = LOG(@m,CAST($PrivateKey AS float)) WHERE IdNIF = $IdNIF;"
        
        sqlcmd ($query2)
    }
    Write-Host "Leucocitos y cociente Colesterol/HDL calculado para todos los pacientes."
}

function InsertNotes{
    param(
        [Parameter(Mandatory=$True)]
        [decimal]$NIF,
        [Parameter(Mandatory=$True)]
        [decimal]$Practica1,
        [Parameter(Mandatory=$True)]
        [decimal]$Practica2,
        [Parameter(Mandatory=$True)]
        [decimal]$Practica3,
        [Parameter(Mandatory=$True)]
        [decimal]$Practica4,
        [Parameter(Mandatory=$True)]
        [decimal]$Examen
    )
    $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $NIF
    $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF

    $Practica1 = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Practica1
    $Practica2 = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Practica2
    $Practica3 = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Practica3
    $Practica4 = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Practica4
    $Examen = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Examen
    
    sqlcmd "INSERT INTO dbo.Criptografia (IdNIF, Practica1, Practica2, Practica3, Practica4, Examen) VALUES ($IdNIF, $Practica1, $Practica2, $Practica3, $Practica4, $Examen);"
    Write-Host "Notas del alumno con NIF:$NIF cifrado $DNICrypt insertadas."
}

function UpdateNote{
    param(
        [Parameter(Mandatory=$True)]
        [decimal]$NIF,
        [Parameter(Mandatory=$True)]
        [string]$Actividad,
        [Parameter(Mandatory=$True)]
        [decimal]$Nota
    )
    $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $NIF
    $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF
    
    $NotaCrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $Nota
    $OldNoteCrypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").$Actividad
    $OldNote = CryptoHEL -Passphrase $Passphrase -Value $OldNoteCrypt
    Write-Host "La nota anterior de $Actividad era: $OldNote y ha sido modificada por: $Nota" -ForegroundColor Red
    sqlcmd "UPDATE dbo.Criptografia SET $Actividad = $NotaCrypt WHERE IdNIF = $IdNIF;"
    Write-Host "Nota $Actividad del alumno con NIF:$NIF cifrado $DNICrypt actualizada."
}

function MediaPracticas{
    param(
        [Parameter(Mandatory=$True)]
        [decimal[]]$NIFs,
        [Parameter(Mandatory=$True)]
        [int]$NumPracticas
    )
    $PrivateKey = CryptoHEL -Passphrase $Passphrase -PrivateKey

    $NIFs | ForEach-Object {
        $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $_
        $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF

        $Practica1Crypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").Practica1
        $Practica2Crypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").Practica2
        $Practica3Crypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").Practica3
        $Practica4Crypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").Practica4
        
        #Logarithm property
        $query = "DECLARE @m float;
                  SET @m = (SELECT(ROUND(((POWER(CAST($PrivateKey AS float),$Practica1Crypt) + POWER(CAST($PrivateKey AS float),$Practica2Crypt) + POWER(CAST($PrivateKey AS float),$Practica3Crypt) + POWER(CAST($PrivateKey AS float),$Practica4Crypt)) / $NumPracticas),3)));
                  UPDATE dbo.Criptografia SET MediaPracticas = LOG(@m,CAST($PrivateKey AS float)) WHERE IdNIF = $IdNIF;"

        sqlcmd($query)
    }
    Write-Host "Nota media practicas calculadas para todos los alumnos."
}

function NotaFinal{
    param(
        [Parameter(Mandatory=$True)]
        [decimal[]]$NIFs
    )
    $NotasFinales = @()
    $PrivateKey = CryptoHEL -Passphrase $Passphrase -PrivateKey

    $NIFs | ForEach-Object {
        $DNICrypt = CryptoHEL -Passphrase $Passphrase -Encrypt -Value $_
        $IdNIF = (sqlcmd "SELECT * FROM dbo.NIF WHERE NIF = $DNICrypt").IdNIF
        $MediaPracticasCrypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").MediaPracticas
        $ExamenCrypt = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF;").Examen

        #Logarithm property
        $query = "DECLARE @m float;
                  SET @m = (SELECT(ROUND((POWER(CAST($PrivateKey AS float),$MediaPracticasCrypt) * 0.4) + (POWER(CAST($PrivateKey AS float),$ExamenCrypt) * 0.6),3)));
                  UPDATE dbo.Criptografia SET NotaFinal = LOG(@m,CAST($PrivateKey AS float)) WHERE IdNIF = $IdNIF;"
        
        sqlcmd ($query)
        $NotaCrypted = (sqlcmd "SELECT * FROM dbo.Criptografia WHERE IdNIF = $IdNIF").Notafinal
        $NotasFinales += CryptoHEL -Passphrase $Passphrase -Value  $NotaCrypted
    }

    return $NotasFinales
}

##### Variables #####
$NIFUser1 = "12345678"
$NIFUser2 = "25422954"
$NIFUserDemo = "87654321"
$NIFs = @($NIFUser1,$NIFUser2,$NIFUserDemo)

##### Main #####
if(Test-Path -Path ".\Confidential1.txt"){
    Write-Host "Cambiar Passphrase: [y/n]" -ForegroundColor Green
    do{
        $reply = Read-Host
        $reply = $reply.ToLower()
        if($reply -eq "y" -or $reply -eq "n"){
            $Check = $true
        }else{
            Write-Host "Respuesta incorrecta, reintente de nuevo: [y/n]" -ForegroundColor Yellow
            $Check = $false
        }
    }while($Check -eq $false)
    if($reply -eq "y"){
        Remove-Item -Path ".\Confidential1.txt"
    }
}
$Passphrase = Confidential -Info "Passphrase"
$UserSQL = Confidential -Info "UserSQL"
$PasswordSQL = Confidential -Info "PasswordSQL"

# Checking if data introduced is correct
$TestConnection = sqlcmd('SELECT @@version')
if($null -eq $TestConnection.Column1){
    Write-Host "Autenticacion SQL incorrecta, eliminamos credenciales SQL, por favor, revise el firewall e intentelo de nuevo." -ForegroundColor Green
    Remove-Item -Path ".\Confidential2.txt" -Force
    exit
}

Write-Host "Inicializando base de datos" -ForegroundColor Magenta
sqlcmd("DELETE Criptografia;
        DELETE Analisis;
        DELETE NIF;
        DELETE Standards;
        DBCC CHECKIDENT ('[NIF]', RESEED, 0);
        DBCC CHECKIDENT ('[Standards]', RESEED, 0);
        DBCC CHECKIDENT ('[Criptografia]', RESEED, 0);
        DBCC CHECKIDENT ('[Analisis]', RESEED, 0);")

Write-Host "Insertando NIF Usuario 1..." -ForegroundColor Yellow
InsertNIF -NIF $NIFUser1

Write-Host "Insertando NIF Usuario 2..." -ForegroundColor Yellow
InsertNIF -NIF $NIFUser2

Write-Host "Insertando Usuario Demo..." -ForegroundColor Green
InsertNIF -NIF $NIFUserDemo

Write-Host "Insertando valores Standards" -ForegroundColor Magenta
InsertStandards -Nota 5 -LeucocitosInfValue 4 -LeucocitosSupValue 11 -CocienteCOLValue 4.5

Write-Host "Insertando Analisis Paciente 1..." -ForegroundColor Yellow
InsertAnalisis -NIF $NIFUser1 -NumAnalisis 4 -Linfocitos 3.13 -Monocitos 2.68 -Colesterol 128.6 -HDL 43

Write-Host "Insertando Analisis Paciente 2..." -ForegroundColor Yellow
InsertAnalisis -NIF $NIFUser2 -NumAnalisis 55 -Linfocitos 1.78 -Monocitos 1.52 -Colesterol 356 -HDL 54

Write-Host "Insertando Analisis Paciente Demo..." -ForegroundColor Green
InsertAnalisis -NIF $NIFUserDemo -NumAnalisis 2 -Linfocitos 1 -Monocitos 2.38 -Colesterol 115 -HDL 39

Write-Host "Calculando Leucocitos y Cociente Colesterol/HDL..." -ForegroundColor Green
CalcResultadosAnalisis -NIFs $NIFs

$Pacientes = (sqlcmd ("SELECT COUNT (DISTINCT IdNIF) FROM dbo.Analisis")).Column1
Write-Host "El numero de pacientes totales es de: $Pacientes" -ForegroundColor Green


Write-Host "`n------------------------------------------------------------`n" -ForegroundColor DarkBlue

Write-Host "Insertando Notas Alumno 1..." -ForegroundColor Yellow
InsertNotes -NIF $NIFUser1 -Practica1 7.2 -Practica2 10 -Practica3 9.5 -Practica4 8.2 -Examen 9.1

Write-Host "Insertando Notas Alumno 2..." -ForegroundColor Yellow
InsertNotes -NIF $NIFUser2 -Practica1 8.2 -Practica2 5 -Practica3 6.5 -Practica4 7.2 -Examen 4.1

Write-Host "Insertando Notas Alumno Demo..." -ForegroundColor Green
InsertNotes -NIF $NIFUserDemo -Practica1 6.1 -Practica2 7.4 -Practica3 5.5 -Practica4 4.9 -Examen 7.5

# Teacher could forget review last question (+2.5 marks)
Write-Host "Actualizando Nota Alumno Demo..." -ForegroundColor Green
UpdateNote -NIF $NIFUserDemo -Actividad "Examen" -Nota 2.1

Write-Host "Calculando media practicas de los alumnos..." -ForegroundColor Green
MediaPracticas -NIFs $NIFs -NumPracticas 4

Write-Host "Cargando notas finales del alumno..." -ForegroundColor Green
$NotasFinales = NotaFinal -NIFs $NIFs

Write-Host "`n Notas finales cargadas, mostrando:" -ForegroundColor Cyan

# Writing on the screen
$obj = New-Object 'system.collections.generic.dictionary[decimal,decimal]'
$i = 0
$NIFs | ForEach-Object {
    $obj.Add($_,$NotasFinales[$i])
    $i++
}

$obj | Format-Table @{l='NIF';e={$_.Key}},@{l='NotaFinal';e={$_.Value}}

$NotaStandardCrypt = (sqlcmd "SELECT * FROM dbo.Standards WHERE Standard = 'Nota'").Value
$Aprobados = (sqlcmd ("SELECT COUNT (DISTINCT IdNIF) FROM dbo.Criptografia WHERE NotaFinal >= $NotaStandardCrypt")).Column1
$Alumnos = (sqlcmd ("SELECT COUNT (DISTINCT IdNIF) FROM dbo.Criptografia")).Column1
$Porcentaje = [math]::Round(($Aprobados * 100) / $Alumnos)
Write-Host "El numero de alumnos aprobados es de: $Aprobados, un $Porcentaje %" -ForegroundColor Green
Write-Host "`nEl script ha terminado, have a nice day!" -ForegroundColor DarkBlue