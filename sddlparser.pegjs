sddl = owner_string?  group_string?  dacl_string?  sacl_string?
  
 owner_string = "O:"  sid:sid_string { return "Owner: " + sid; }
  
 group_string = "G:"  sid:sid_string { return "Group: " + sid; } 
  
 dacl_string = "D:"  flags:acl_flag_string  aces:aces { return "DACL " + flags + " \n" + aces; }
  
 sacl_string = "S:"  flags:acl_flag_string  aces:aces { return "SACL " + flags + " \n" + aces; }
  
 sid_string = sid_token / sid_value
  
 sid_value = SID
  
 sid_token = 
    "DA" { return "Domain admins"; } /
    "DG" { return "Domain guests"; } /
    "DU" { return "Domain users"; } /
    "ED" { return "Enterprise domain controllers"; } /
    "DD" { return "Domain domain controllers"; } /
    "DC" { return "Domain computers"; } /
    "BA" { return "Builtin (local) administrators"; } /
    "BG" { return "Builtin (local) guests"; } /
    "BU" { return "Builtin (local) users"; } /
    "LA" { return "Local administrator account"; } /
    "LG" { return "Local group account"; } /
    "AO" { return "Account operators"; } /
    "BO" { return "Backup operators"; } /
    "PO" { return "Printer operators"; } /
    "SO" { return "Server operators"; } /
    "AU" { return "Authenticated users"; } /
    "PS" { return "Personal self"; } /
    "CO" { return "Creator owner"; } /
    "CG" { return "Creator group"; } /
    "SY" { return "Local system"; } /
    "PU" { return "Power users"; } /
    "WD" { return "Everyone ( World )"; } /
    "RE" { return "Replicator"; } /
    "IU" { return "Interactive logon user"; } /
    "NU" { return "Nework logon user"; } /
    "SU" { return "Service logon user"; } /
    "RC" { return "Restricted code"; } /
    "WR" { return "Write Restricted code"; } /
    "AN" { return "Anonymous Logon"; } /
    "SA" { return "Schema Administrators"; } /
    "CA" { return "Certificate Server Administrators"; } /
    "RS" { return "RAS servers group"; } /
    "EA" { return "Enterprise administrators"; } /
    "PA" { return "Group Policy administrators"; } /
    "RU" { return "alias to allow previous windows 2000"; } /
    "LS" { return "Local service account (for services)"; } /
    "NS" { return "Network service account (for services)"; } /
    "RD" { return "Remote desktop users (for terminal server)"; } /
    "NO" { return "Network configuration operators ( to manage configuration of networking features)"; } /
    "MU" { return "Performance Monitor Users"; } /
    "LU" { return "Performance Log Users"; } /
    "IS" { return "Anonymous Internet Users"; } /
    "CY" { return "Crypto Operators"; } /
    "OW" { return "Owner Rights SID"; } /
    "ER" { return "Event log readers"; } /
    "RO" { return "Enterprise Read-only domain controllers"; } /
    "CD" { return "Users who can connect to certification authorities using DCOM"; } /
    "AC" { return "All applications running in an app package context"; } /
    "RA" { return "Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources."; } /
    "ES" { return "Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run."; } /
    "MS" { return "Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. "; } /
    "UD" { return "UserMode driver"; } /
    "HA" { return "Members of this group have complete and unrestricted access to all features of Hyper-V. "; } /
    "CN" { return "Members of this group that are domain controllers may be cloned. "; } /
    "AA" { return "Members of this group can remotely query authorization attributes and permissions for resources on this computer. "; } /
    "RM" { return "Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user. "; } /
    "AS" { return "Authentication Authority Asserted"; } /
    "SS" { return "Authentication Service Asserted"; } /
    "AP" { return "Members of this group are afforded additional protections against authentication security threats."; } /
    "KA" { return "Members of this group have full control over all key credential objects in the domain"; } /
    "EK" { return "Members of this group have full control over all key credential objects in the forest"; } /
    "LW" { return "Low mandatory level"; } /
    "ME" { return "Medium mandatory level"; } /
    "MP" { return "Medium Plus mandatory level"; } /
    "HI" { return "High mandatory level"; } /
    "SI" { return "System mandatory level"; }
  
 acl_flag_string = flags:acl_flag* { return flags.length === 0 ? "" : "(flags: " + flags.join(", ") + ")"; }
  
 acl_flag =     
    "P" { return "DACL or SACL Protected"; } /
    "AR" { return "Auto inherit request"; } /
    "AI" { return "DACL/SACL are auto inherited"; } /
    "NO_ACCESS_CONTROL" { return "Null ACL"; }
  
 aces = aces:(ace / conditional_ace / resource_attribute_ace)*
 { return "\t" + aces.join("\n\t"); }
  
 ace = "(" type:ace_type ";" flag:ace_flag_string ";" rights:ace_rights ";" 
 objguid:object_guid? ";" inhobjguid:inherit_object_guid? ";" sid:sid_string ")"
 { return type + " on " + rights + " for " + sid; }
  
 ace_type = 
     "A" { return "Access allowed"; } /
    "D" { return "Access denied"; } /
    "OA" { return "Object access allowed"; } /
    "OD" { return "Object access denied"; } /
    "AU" { return "Audit"; } /
    "AL" { return "Alarm"; } /
    "OU" { return "Object audit"; } /
    "OL" { return "Object alarm"; } /
    "ML" { return "Integrity label"; } /
    "TL" { return "Process trust label"; } /
    "XA" { return "Callback access allowed"; } /
    "XD" { return "Callback access denied"; } /
    "RA" { return "Resource attribute"; } /
    "SP" { return "Scoped policy"; } /
    "XU" { return "Callback audit"; } /
    "ZA" { return "Callback object access allowed"; }

  
 conditional_ace = "(" conditional_ace_type ";" ace_flag_string? ";" ace_rights 
 ";" object_guid? ";" inherit_object_guid? ";" sid_string ";" "(" cond_expr ")" ")"
  
 conditional_ace_type = "XA" / "XD" / "ZA" / "XU"
  
 central_policy_ace = "(" "SP" ";" ace_flag_string? ";;;;" capid_value_sid")"
  
 capid_value_sid = "S-1-17-" SubAuthority+ 
  
 resource_attribute_ace = "(" "RA" ";" ace_flag_string? ";;;;" ( "WD" / 
 "S-1-1-0" ) ";(" attribute_data "))"
 DQUOTE = "\""
 
 attribute_data = DQUOTE attr_char2+ DQUOTE "," ( TI_attr / TU_attr / TS_attr / 
 TD_attr / TX_attr / TB_attr )
  
 TI_attr = "TI" "," attr_flags ("," int_64)*
  
 TU_attr = "TU" "," attr_flags ("," uint_64)*
  
 TS_attr = "TS" "," attr_flags ("," char_string)*
  
 TD_attr = "TD" "," attr_flags ("," sid_string)*
  
 TX_attr = "TX" "," attr_flags ("," octet_string)*
  
 TB_attr = "TB" "," attr_flags ("," ( "0" / "1" ) )*
  
 attr_flags = "0x" ((HEXDIG_1_4? "00")? sys_attr_flags / "0"* sys_attr_flags / 
 "0"* HEXDIG)
 
 HEXDIG = [a-fA-F0-9]
 HEXDIG_1_2 = left:HEXDIG right:HEXDIG? { return left + (right || ""); }
 HEXDIG_1_4 = left:HEXDIG_1_2 right:HEXDIG_1_2? { return left + (right || ""); }
 HEXDIG_1_8 = left:HEXDIG_1_4 right:HEXDIG_1_4? { return left + (right || ""); }
 HEXDIG_1_12 = left:HEXDIG_1_8 right:HEXDIG_1_4? { return left + (right || ""); }
 HEXDIG_4 = a:HEXDIG b:HEXDIG c:HEXDIG d:HEXDIG { return a + b + c + d; }
 HEXDIG_8 = left:HEXDIG_4 right:HEXDIG_4 { return left + right; }
 HEXDIG_12 = left:HEXDIG_8 right:HEXDIG_4 { return left + right; }
 
 sys_attr_flags = ( "0"/ "1" / "2" / "3" ) HEXDIG
  
 ace_flag_string = ace_flag  ace_flag_string / ""
  
 ace_flag = "CI" / "OI" / "NP" / "IO" / "ID" / "SA" / "FA"
 
 OCTDIG = [0-7]
 DIGIT = [0-9]
 
 ace_rights = 
    ("0x" v:HEXDIG_1_8 { return "0x" + v; }) / 
    ("0" v:OCTDIG+ { return "0" + v; }) / 
    (v:DIGIT+ { return v; }) / 
    (textrights:(text_rights_string*) { return textrights.join(", "); } )
   
 text_rights_string = generic_right / standard_right / object_specific_right
    
 generic_right =
 "GA" { return "General all"; } / 
 "GW" { return "General write"; } / 
 "GR" { return "General read"; } / 
 "GX" { return "General execute"; } 
    
 standard_right = 
 "WO" { return "Write owner"; } / 
 "WD" { return "Write DAC"; } / 
 "RC" { return "Read control"; } / 
 "SD" { return "Standard delete"; }
  
 object_specific_right = 
 "RP" { return "Read property"; } /
"WP" { return "Write property"; } /
"CC" { return "Create child"; } /
"DC" { return "Delete child"; } /
"LC" { return "List children"; } /
"SW" { return "Self write"; } /
"LO" { return "List object"; } /
"DT" { return "Delete tree"; } /
"CR" { return "Control access"; } /
"RC" { return "Read control"; } /
"WD" { return "Write dac"; } /
"WO" { return "Write owner"; } /
"SD" { return "Standard delete"; } /
"GA" { return "Generic all"; } /
"GR" { return "Generic read"; } /
"GW" { return "Generic write"; } /
"GX" { return "Generic execute"; } /
"FA" { return "File all"; } /
"FR" { return "File read"; } /
"FW" { return "File write"; } /
"FX" { return "File execute"; } /
"KA" { return "Key all"; } /
"KR" { return "Key read"; } /
"KW" { return "Key write"; } /
"KX" { return "Key execute"; } /
"NW" { return "No write up"; } /
"NR" { return "No read up"; } /
"NX" { return "No execute up"; }

  
 guid = "" / HEXDIG_8 "-" HEXDIG_4 "-" HEXDIG_4 "-" HEXDIG_4 "-" HEXDIG_12
  
 // The second option is the GUID of the object in the form 
// "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" Where each "X" is a Hex digit
  
 object_guid = guid
  
 inherit_object_guid = guid
  
 wspace = [ \t\n\r]+
  
 term = wspace? (memberof_op / exists_op / rel_op / contains_op / anyof_op / attr_name 
 / rel_op2) wspace?
  
 cond_expr = term / term wspace? ("||" / "&&" ) wspace? cond_expr / ("!"? wspace? 
 "(" cond_expr ")")
 memberof_op = ( "Member_of" / "Not_Member_of" / "Member_of_Any" / 
 "Not_Member_of_Any" / "Device_Member_of" / "Device_Member_of_Any" / 
 "Not_Device_Member_of" / "Not_Device_Member_of_Any" ) wspace sid_array
  
 exists_op = ( "Exists" / "Not_exists") wspace attr_name
  
 rel_op = attr_name wspace? ("<" / "<=" / ">" / ">=") wspace? (attr_name2 / value) 
   // only scalars
 rel_op2 = attr_name wspace? ("==" / "!=") wspace? ( attr_name2 / value_array )
   // scalar or list
 contains_op = attr_name wspace ("Contains" / "Not_Contains") wspace (attr_name2 / value_array)
  
 anyof_op = attr_name wspace ("Any_of" / "Not_Any_of") wspace (attr_name2 / value_array)
  
 attr_name1 = attr_char1 (attr_char1 / "@")*              
   // old simple name
  ALPHA = [a-zA-Z]
 attr_char1 = (ALPHA / DIGIT / ":" / "." / "/" / "_")+
  
 attr_name2 = ("@user." / "@device." / "@resource.") attr_char2+ 
   // new prefixed name form
  
 attr_char2 = attr_char1 / lit_char
  
 attr_name = attr_name1 / attr_name2                       
   // either name form
  
 sid_array = literal_SID wspace? / "{" wspace? literal_SID wspace? ( "," wspace? literal_SID wspace?)* "}"
  
 literal_SID = "SID(" sid_string ")"
  
 value_array = value wspace? / "{" wspace? value wspace? ("," wspace? value wspace?)* "}"
  
 value = int_64 / char_string / octet_string
  
 int_64 = ("+" / "-")? ("0x" HEXDIG+) / ("0" OCTDIG+) / DIGIT+
   // values must fit within 64 bits in two's complement form
  
 uint_64 = ("0x" HEXDIG+) / ("0" OCTDIG+) / DIGIT+  
   // values must fit within 64 bits
 
 CHAR = [\x01-\x7F]
 char_string = DQUOTE (CHAR)* DQUOTE
  
 octet_string = "#" (HEXDIG HEXDIG)*
  
 lit_char = "#" / "$" / "'" / "*" / "+" / "-" / "." / "/" / ":" / ";" / "?" / 
 "@" / "[" / "\\" / "]" / "^" / "_" / "`" / "{" / "}" / "~" / [\x80-\xFFFF] / 
 ( "%" HEXDIG_4)
   // 4HEXDIG can have any value except 0000 (NULL)

SID= "S-1-" i:IdentifierAuthority s:SubAuthority+
{ return "S-1-" + i + "-" + s.join("-"); }

IdentifierAuthority= IdentifierAuthorityDec / IdentifierAuthorityHex
   // If the identifier authority is < 2^32, the
   // identifier authority is represented as a decimal 
   // number
   // If the identifier authority is >= 2^32,
   // the identifier authority is represented in 
   // hexadecimal
DIGIT_1_2 = a:DIGIT b:DIGIT? { return a + (b ? b : ""); }
DIGIT_1_4 = a:DIGIT_1_2 b:DIGIT_1_2?  { return a + (b ? b : ""); }
DIGIT_1_8 = a:DIGIT_1_4 b:DIGIT_1_4?  { return a + (b ? b : ""); }
DIGIT_1_10 = a:DIGIT_1_8 b:DIGIT_1_2?  { return a + (b ? b : ""); }

 IdentifierAuthorityDec =  DIGIT_1_10
   // IdentifierAuthorityDec, top level authority of a 
   // security identifier is represented as a decimal number
  
 IdentifierAuthorityHex = "0x" HEXDIG_12
   // IdentifierAuthorityHex, the top-level authority of a
   // security identifier is represented as a hexadecimal number
 SubAuthority= "-" a:DIGIT_1_10 { return a; }
   // Sub-Authority is always represented as a decimal number 
   // No leading "0" characters are allowed when IdentifierAuthority
   // or SubAuthority is represented as a decimal number
   // All hexadecimal digits must be output in string format,
   // pre-pended by "0x"
