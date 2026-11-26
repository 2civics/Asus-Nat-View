<#PSScriptInfo

.VERSION 1.0.0

.GUID 8d9d0938-28c8-4452-aa33-da63453870d0

.AUTHOR waresoft

.COMPANYNAME waresoft

.COPYRIGHT (c) 2026 waresoft. All rights reserved.

.TAGS ASUS Asuswrt Merlin iptables NAT Firewall SSH WPF GUI Router

.LICENSEURI https://opensource.org/licenses/MIT

.RELEASENOTES
Initial public release of **AsusNatView** (`AsusNatView.ps1`), a compact Windows WPF utility for inspecting live `iptables` NAT chains on ASUS routers over SSH.

### Highlights
* **Read-Only NAT Inspection:** Queries `iptables -t nat -L <CHAIN> -v -n -x` over OpenSSH key authentication without modifying router state.
* **Chain Switching:** Built-in selector for `PREROUTING`, `POSTROUTING`, and `VSERVER` (configurable in the script header).
* **Live Search Filtering:** Filters displayed rules in real time across targets, protocols, interfaces, IP addresses, ports, and rule details.
* **Exact Packet & Byte Counters:** Right-aligned unrounded packet and byte totals with `F5` refresh and `Esc` to close.
* **Native Windows Theme Support:** Automatically matches your Windows 10/11 dark or light app theme (including DWM title bars) or accepts manual `Dark` / `Light` overrides.

### Requirements
* Windows 10 / 11 with PowerShell 5.1 or PowerShell 7+
* Built-in Windows OpenSSH Client (`ssh.exe`)
* ASUS router (Asuswrt or Asuswrt-Merlin) with SSH key authentication configured

#>

#

<#
.DESCRIPTION
    A lightweight, read-only Windows WPF GUI for inspecting live `iptables` NAT rules (`PREROUTING`, `POSTROUTING`, `VSERVER`) on ASUS (Asuswrt / Asuswrt-Merlin) routers over SSH.
#>

.SYNOPSIS
    Displays live iptables NAT rules from an ASUS (Asuswrt) router in a compact WPF window.

.DESCRIPTION
    Connects to an ASUS router over SSH using key-based authentication, queries the
    specified iptables NAT chain, and renders packetbyte counters and rule details
    in a dark-mode-aware WPF DataGrid with real-time search filtering.

.PARAMETER RouterIP
    IP address or hostname of the ASUS router. Defaults to 192.168.50.1.

.PARAMETER User
    SSH username on the router. Defaults to admin.

.PARAMETER KeyPath
    Path to the OpenSSH private key used for authentication. Defaults to $envUSERPROFILE.sshid_ed25519.

.PARAMETER DeviceLabel
    Friendly router label displayed in the window title and error dialogs.

.PARAMETER Chains
    List of iptables NAT chains available in the dropdown selector.

.PARAMETER DefaultChain
    Initial NAT chain loaded on startup. Defaults to PREROUTING.

.PARAMETER Theme
    UI color theme Auto (matches Windows app theme), Dark, or Light.

.EXAMPLE
    .Show-AsusNatRules.ps1

.EXAMPLE
    .Show-AsusNatRules.ps1 -RouterIP 192.168.1.1 -KeyPath $envUSERPROFILE.sshasus_ed25519 -DeviceLabel RT-AX86U
#

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Enable native Windows 10/11 dark title bar support
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DwmTheme {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);
}
"@ -ErrorAction SilentlyContinue

# --- Configuration ---
$RouterIP     = "192.168.50.1"
$User         = "admin"
$KeyPath      = "$env:USERPROFILE\.ssh\id_ed25519"
$DeviceLabel  = "ASUS Router"
$Chains       = @("PREROUTING", "POSTROUTING", "VSERVER")
$DefaultChain = "PREROUTING"
$Theme        = "Auto"   # Options: "Auto", "Dark", "Light"

# --- Detect Windows Theme ---
if ($Theme -eq "Auto") {
    $AppsLight = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction SilentlyContinue).AppsUseLightTheme
    $IsDark = ($AppsLight -eq 0)
} else {
    $IsDark = ($Theme -eq "Dark")
}

$Palette = if ($IsDark) {
    @{
        WindowBg  = "#1E1E1E"
        SurfaceBg = "#252526"
        HeaderBg  = "#2D2D30"
        HoverBg   = "#37373D"
        SelectBg  = "#264F78"
        Border    = "#3F3F46"
        GridLine  = "#2D2D30"
        Text      = "#F0F0F0"
        MutedText = "#A0A0A0"
    }
} else {
    @{
        WindowBg  = "#F3F3F3"
        SurfaceBg = "#FFFFFF"
        HeaderBg  = "#EAEAEA"
        HoverBg   = "#E2E2E2"
        SelectBg  = "#CCE8FF"
        Border    = "#CCCCCC"
        GridLine  = "#E5E5E5"
        Text      = "#1A1A1A"
        MutedText = "#666666"
    }
}

# --- Fetch & Parse NAT Rules ---
function Get-NatRules {
    param([string]$Chain)
    if ($Chain -notmatch '^[A-Za-z0-9_-]+$') {
        throw "Invalid chain name: $Chain"
    }
    $RawOutput = ssh -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=5 -i $KeyPath "$User@$RouterIP" "iptables -t nat -L $Chain -v -n -x" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $RawOutput) {
        $ErrDetail = ($RawOutput | Out-String).Trim()
        if (-not $ErrDetail) { $ErrDetail = "Router unreachable or SSH authentication failed." }
        throw "Unable to retrieve $Chain rules from $RouterIP.`n`n$ErrDetail"
    }
    $Lines  = @($RawOutput) -split "\r?\n"
    $Header = ($Lines | Where-Object { $_ -match '^Chain\s+' } | Select-Object -First 1) -replace '^Chain\s+', ''
    if (-not $Header) { $Header = $Chain }
    $Rules = @(
        $Lines | Where-Object {
            $_.Trim() -ne "" -and $_ -notmatch '^Chain\s+' -and $_ -notmatch '^\s*pkts\s+bytes'
        } | ForEach-Object {
            $Cols = $_.Trim() -split '\s+'
            if ($Cols.Count -ge 9) {
                [PSCustomObject]@{
                    Packets     = if ($Cols[0] -match '^\d+$') { [int64]$Cols[0] } else { $Cols[0] }
                    Bytes       = if ($Cols[1] -match '^\d+$') { [int64]$Cols[1] } else { $Cols[1] }
                    Target      = $Cols[2]
                    Protocol    = $Cols[3]
                    Opt         = $Cols[4]
                    In          = $Cols[5]
                    Out         = $Cols[6]
                    Source      = $Cols[7]
                    Destination = $Cols[8]
                    RuleDetails = if ($Cols.Count -gt 9) { $Cols[9..($Cols.Count - 1)] -join ' ' } else { "-" }
                }
            }
        }
    )
    return @{ Header = $Header; Rules = $Rules }
}

# Initial fetch before building the window
try {
    $InitialData = Get-NatRules -Chain $DefaultChain
}
catch {
    [System.Windows.MessageBox]::Show($_.Exception.Message, "$DeviceLabel Firewall", "OK", "Error") | Out-Null
    exit 1
}

# --- Build Compact WPF UI ---
[xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$DeviceLabel NAT - $($InitialData.Header)"
        SizeToContent="WidthAndHeight"
        MinWidth="680" MaxWidth="1150"
        MinHeight="210" MaxHeight="620"
        WindowStartupLocation="CenterScreen"
        Background="$($Palette.WindowBg)"
        Foreground="$($Palette.Text)"
        FontFamily="Segoe UI" FontSize="12.5">
    <Window.Resources>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="$($Palette.HeaderBg)"/>
            <Setter Property="Foreground" Value="$($Palette.Text)"/>
            <Setter Property="BorderBrush" Value="$($Palette.Border)"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" Padding="10,5">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="$($Palette.SelectBg)"/>
                    <Setter Property="Foreground" Value="$($Palette.Text)"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="ComboBoxItem">
            <Setter Property="Background" Value="$($Palette.SurfaceBg)"/>
            <Setter Property="Foreground" Value="$($Palette.Text)"/>
            <Setter Property="Padding" Value="8,5"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="IsHighlighted" Value="True">
                    <Setter Property="Background" Value="$($Palette.SelectBg)"/>
                    <Setter Property="Foreground" Value="$($Palette.Text)"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="ComboBox">
            <Setter Property="Foreground" Value="$($Palette.Text)"/>
            <Setter Property="Background" Value="$($Palette.SurfaceBg)"/>
            <Setter Property="BorderBrush" Value="$($Palette.Border)"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Background="{TemplateBinding Background}"
                                          BorderBrush="{TemplateBinding BorderBrush}"
                                          BorderThickness="{TemplateBinding BorderThickness}"
                                          Focusable="False"
                                          IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press">
                                <ToggleButton.Template>
                                    <ControlTemplate TargetType="ToggleButton">
                                        <Border Background="{TemplateBinding Background}"
                                                BorderBrush="{TemplateBinding BorderBrush}"
                                                BorderThickness="{TemplateBinding BorderThickness}">
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="22"/>
                                                </Grid.ColumnDefinitions>
                                                <Path Grid.Column="1" HorizontalAlignment="Center" VerticalAlignment="Center"
                                                      Data="M 0 0 L 4 4 L 8 0 Z" Fill="$($Palette.MutedText)"/>
                                            </Grid>
                                        </Border>
                                    </ControlTemplate>
                                </ToggleButton.Template>
                            </ToggleButton>
                            <ContentPresenter IsHitTestVisible="False"
                                              Content="{TemplateBinding SelectionBoxItem}"
                                              ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                              ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                              Margin="8,4,24,4"
                                              VerticalAlignment="Center"
                                              HorizontalAlignment="Left"/>
                            <Popup Placement="Bottom"
                                   IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True"
                                   Focusable="False"
                                   PopupAnimation="Slide">
                                <Grid SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}"
                                      MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border Background="$($Palette.SurfaceBg)"
                                            BorderThickness="1"
                                            BorderBrush="$($Palette.Border)"/>
                                    <ScrollViewer Margin="1" SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="FlatButton" TargetType="Button">
            <Setter Property="Background" Value="$($Palette.HeaderBg)"/>
            <Setter Property="Foreground" Value="$($Palette.Text)"/>
            <Setter Property="BorderBrush" Value="$($Palette.Border)"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="BtnBorder"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="BtnBorder" Property="Background" Value="$($Palette.HoverBg)"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Top Chain Selector, Filter & Refresh Bar -->
        <Grid Grid.Row="0" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="135"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <TextBlock Grid.Column="0" Text="Chain:" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="$($Palette.MutedText)"/>
            <ComboBox x:Name="ChainBox" Grid.Column="1" Margin="0,0,14,0" VerticalContentAlignment="Center"/>

            <TextBlock Grid.Column="2" Text="Filter:" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="$($Palette.MutedText)"/>
            <TextBox x:Name="SearchBox" Grid.Column="3"
                     Background="$($Palette.SurfaceBg)" Foreground="$($Palette.Text)"
                     BorderBrush="$($Palette.Border)" CaretBrush="$($Palette.Text)"
                     Padding="6,4" VerticalContentAlignment="Center"/>

            <Button x:Name="RefreshBtn" Grid.Column="4" Content="Refresh (F5)"
                    Style="{StaticResource FlatButton}" Margin="8,0,0,0"/>
        </Grid>

        <!-- NAT Rules Table -->
        <DataGrid x:Name="RulesGrid" Grid.Row="1"
                  AutoGenerateColumns="True" IsReadOnly="True"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                  HorizontalGridLinesBrush="$($Palette.GridLine)"
                  Background="$($Palette.SurfaceBg)" Foreground="$($Palette.Text)"
                  RowBackground="$($Palette.SurfaceBg)"
                  AlternatingRowBackground="$($Palette.WindowBg)"
                  BorderBrush="$($Palette.Border)" BorderThickness="1"
                  CanUserAddRows="False" CanUserDeleteRows="False" CanUserResizeRows="False"
                  SelectionMode="Extended" SelectionUnit="FullRow"/>

        <!-- Compact Status Footer -->
        <DockPanel Grid.Row="2" Margin="0,8,0,0">
            <TextBlock x:Name="StatusText" DockPanel.Dock="Left" Foreground="$($Palette.MutedText)" FontSize="11.5"/>
            <TextBlock Text="Esc to close" DockPanel.Dock="Right" HorizontalAlignment="Right" Foreground="$($Palette.MutedText)" FontSize="11.5"/>
        </DockPanel>
    </Grid>
</Window>
"@

$Reader     = New-Object System.Xml.XmlNodeReader $Xaml
$Window     = [Windows.Markup.XamlReader]::Load($Reader)
$ChainBox   = $Window.FindName("ChainBox")
$SearchBox  = $Window.FindName("SearchBox")
$RefreshBtn = $Window.FindName("RefreshBtn")
$RulesGrid  = $Window.FindName("RulesGrid")
$StatusText = $Window.FindName("StatusText")

# Populate Chain dropdown before attaching SelectionChanged
foreach ($C in $Chains) { [void]$ChainBox.Items.Add($C) }
$ChainBox.SelectedItem = $DefaultChain

# Apply Windows 10/11 Dark Title Bar
$Window.Add_SourceInitialized({
    $Hwnd = (New-Object System.Windows.Interop.WindowInteropHelper($Window)).Handle
    $UseDark = if ($IsDark) { 1 } else { 0 }
    [void][DwmTheme]::DwmSetWindowAttribute($Hwnd, 20, [ref]$UseDark, 4)
    [void][DwmTheme]::DwmSetWindowAttribute($Hwnd, 19, [ref]$UseDark, 4)
})

# Lock initial compact size once rendered so live filtering doesn't resize the window
$Window.Add_ContentRendered({
    $Window.SizeToContent = 'Manual'
    $SearchBox.Focus() | Out-Null
})

# Right-align numeric columns
$RulesGrid.Add_AutoGeneratingColumn({
    param($Sender, $EventArgs)
    if ($EventArgs.PropertyName -in @("Packets", "Bytes")) {
        $RightStyle = New-Object System.Windows.Style([System.Windows.Controls.TextBlock])
        $RightStyle.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.TextBlock]::TextAlignmentProperty, [System.Windows.TextAlignment]::Right)))
        $EventArgs.Column.ElementStyle = $RightStyle
    }
})

# Bind data & live filter
$Items = New-Object System.Collections.ObjectModel.ObservableCollection[object]
foreach ($Rule in $InitialData.Rules) { $Items.Add($Rule) }
$RulesGrid.ItemsSource = $Items

$View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($RulesGrid.ItemsSource)
$View.Filter = {
    param($Item)
    if ([string]::IsNullOrWhiteSpace($SearchBox.Text)) { return $true }
    $Query = $SearchBox.Text.Trim()
    foreach ($Prop in $Item.PSObject.Properties) {
        if ($null -ne $Prop.Value -and $Prop.Value.ToString().IndexOf($Query, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

$UpdateStatus = {
    $SelectedChain = $ChainBox.SelectedItem
    if ($Items.Count -eq 0) {
        $StatusText.Text = "No rules in $SelectedChain chain  |  $RouterIP"
    } else {
        $StatusText.Text = "Showing $($View.Count) of $($Items.Count) rules ($SelectedChain)  |  $RouterIP"
    }
}
& $UpdateStatus

$SearchBox.Add_TextChanged({
    $View.Refresh()
    & $UpdateStatus
})

# Load/Refresh selected chain
$LoadSelectedChain = {
    $TargetChain = $ChainBox.SelectedItem
    $StatusText.Text = "Loading $TargetChain from $RouterIP..."
    $Window.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    try {
        $Fresh = Get-NatRules -Chain $TargetChain
        $Items.Clear()
        foreach ($Rule in $Fresh.Rules) { $Items.Add($Rule) }
        $Window.Title = "$DeviceLabel NAT - $($Fresh.Header)"
        & $UpdateStatus
    }
    catch {
        [System.Windows.MessageBox]::Show($_.Exception.Message, "$DeviceLabel Firewall", "OK", "Error") | Out-Null
        & $UpdateStatus
    }
}

$ChainBox.Add_SelectionChanged($LoadSelectedChain)
$RefreshBtn.Add_Click($LoadSelectedChain)

$Window.Add_KeyDown({
    param($Sender, $EventArgs)
    if ($EventArgs.Key -eq 'Escape') { $Window.Close() }
    elseif ($EventArgs.Key -eq 'F5') { & $LoadSelectedChain }
})

[void]$Window.ShowDialog()

