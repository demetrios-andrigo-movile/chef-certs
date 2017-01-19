<?php
/**
 * Imports a x509 cert/key pair into a chef-vault data bag
 * Imports a rsa   pub/key pair into a chef-vault data bag
 *
 * Alexandre Zia <alexandre@zia.com.br>
 *
 */

define("DATABAG_CHAIN", 'certificate_chains');
define("DATABAG_X509",  'certificates');
define("DATABAG_RSA",   'rsa_keys');
define("DATABAG_SSH",   'ssh_keys');

define("COLOR_BRIGHT", "\033[1;37m");
define("COLOR_GREEN",  "\033[1;32m");
define("COLOR_BLUE",   "\033[1;34m");
define("COLOR_YELLOW", "\033[1;33m");
define("COLOR_RED",    "\033[1;31m");
define("COLOR_RESET",  "\033[0;37m");

define('TYPE_UNKNOWN', 0);
define('TYPE_X509',    1);
define('TYPE_SSH',     2);
define('TYPE_RSA',     3);

define('ACTION_UNKNOWN',      0);
define('ACTION_LIST',         1);
define('ACTION_DETAILS',      2);
define('ACTION_UPDATE',       3);
define('ACTION_EDIT',         4);
define('ACTION_CREATE',       5);
define('ACTION_IMPORT',       6);
define('ACTION_DELETE',       7);
define('ACTION_PERMISSIONS',  8);
define('ACTION_RETRIEVE',     9);
define('ACTION_STATUS',      10);
define('ACTION_BACKUP',      11);

define('SEARCH_QUERY_ACTION_UNKNOWN', 0);
define('SEARCH_QUERY_ACTION_DEL',     1);
define('SEARCH_QUERY_ACTION_ADD',     2);

define('CA_UNKNOWN',      0);
define('CA_ROOT',         1);
define('CA_INTERMEDIATE', 2);

// -----------------------------------------------------
// set defaults

$ACTION            = ACTION_UNKNOWN;
$INPUT_FILE_TYPE   = TYPE_UNKNOWN;
$SEARCH_QUERY      = array();
$KNIFE_CONFIG_FILE = NULL;
$KNIFE_CONFIG      = NULL;
$CERTIFICATE_FILE  = NULL;
$RUN_WIZARD        = NULL;
$DATABAG_NAME      = NULL;
$DATABAG_ITEM      = NULL;
$CHEF_ADMINS       = NULL;
$CHEF_NODES        = NULL;
$ASSUME_YES        = FALSE;
$ADD_SEARCH_TERM   = NULL;
$DEL_SEARCH_TERM   = NULL;

/**
 * Parse command line arguments
 *
 */
function parse_command_line_arguments()
{
  global $_SERVER;
  global $KNIFE_CONFIG_FILE;
  global $CERTIFICATE_FILE;
  global $RUN_WIZARD;
  global $ACTION;
  global $DATABAG_NAME;
  global $DATABAG_ITEM;
  global $SEARCH_QUERY;
  global $ASSUME_YES;
  global $ADD_SEARCH_TERM;
  global $DEL_SEARCH_TERM;

  $long_options = array();

  $options         = "w";
  $long_options[]  = "wizard";

  $options        .= "a:";
  $long_options[]  = "action:";

  $options        .= "c:";
  $long_options[]  = "config_file";

  $options        .= "f:";
  $long_options[]  = "file";

  $options        .= "d:";
  $long_options[]  = "data_bag";

  $options        .= "i:";
  $long_options[]  = "item";

  $options        .= "y";
  $long_options[]  = "yes";

  $options        .= "h";
  $long_options[]  = "help";

  $options        .= "p:";
  $long_options[]  = "add:";

  $options        .= "m:";
  $long_options[]  = "del:";

  $opts = getopt($options, $long_options);

  if(empty($opts))
  {
    usage();
    exit(0);
  }

  foreach ($opts as $argument => $value)
  {
    switch ($argument)
    {
      case 'w':
      case 'wizard':
        $RUN_WIZARD = TRUE;
        break;

      case 'a':
      case 'action':
        switch($value)
        {
          case 'list':        $ACTION = ACTION_LIST;        break;
          case 'details':     $ACTION = ACTION_DETAILS;     break;
          case 'create':      $ACTION = ACTION_CREATE;      break;
          case 'update':      $ACTION = ACTION_UPDATE;      break;
          case 'edit':        $ACTION = ACTION_EDIT;        break;
          case 'permissions': $ACTION = ACTION_PERMISSIONS; break;
          case 'import':      $ACTION = ACTION_IMPORT;      break;
          case 'delete':      $ACTION = ACTION_DELETE;      break;
          case 'retrieve':    $ACTION = ACTION_RETRIEVE;    break;
          case 'status':      $ACTION = ACTION_STATUS;      break;
          case 'backup':      $ACTION = ACTION_BACKUP;      break;
        }
        break;

      case 'c':
      case 'cconfig_file':
        if(empty($value))
        {
          usage();
          exit(1);
        }
        $KNIFE_CONFIG_FILE = $value;
        break;

      case 'f':
      case 'file':
        if(empty($value))
        {
          usage();
          exit(1);
        }
        $CERTIFICATE_FILE = $value;
        break;

      case 'd':
      case 'data_bag':
        if(empty($value))
        {
          usage();
          exit(1);
        }
        $DATABAG_NAME = $value;
        break;

      case 'i':
      case 'item':
        if(empty($value))
        {
          usage();
          exit(1);
        }
        $DATABAG_ITEM = $value;
        break;

      case 'y':
      case 'yes':

        $ASSUME_YES = TRUE;
        break;

      case 'h':
      case 'help':
        switch($ACTION)
        {
          case ACTION_LIST:        help_list();        exit(0); break;
          case ACTION_DETAILS:     help_details();     exit(0); break;
          case ACTION_CREATE:      help_create();      exit(0); break;
          case ACTION_UPDATE:      help_update();      exit(0); break;
          case ACTION_EDIT:        help_edit();        exit(0); break;
          case ACTION_PERMISSIONS: help_permissions(); exit(0); break;
          case ACTION_IMPORT:      help_import();      exit(0); break;
          case ACTION_DELETE:      help_delete();      exit(0); break;
          case ACTION_RETRIEVE:    help_retrieve();    exit(0); break;
          case ACTION_STATUS:      help_status();      exit(0); break;
          case ACTION_BACKUP:      help_backup();      exit(0); break;
        }
        usage();
        exit(0);
        break;

      default:
        usage();
        exit(0);
        break;
    }
  }
}

/**
 * Show usage
 */
function help_header()
{
  // clear screen
  array_map(create_function('$a', 'print chr($a);'), array(27, 91, 72, 27, 91, 50, 74));

  print "
  ".COLOR_BRIGHT."Chef-certs".COLOR_RESET."
  ----------
";
}
/**
 * Show usage
 */
function usage()
{
  global $argv;

  help_header();

  print "
  Manage certificates and keys in Chef data bags to be used by cookbooks:

  Supported certificates and keys:

  * ".COLOR_BRIGHT."Web servers".COLOR_RESET."   'x509 certificate & key'   via cookbook: ".COLOR_BRIGHT."ssl-certificate".COLOR_RESET."
  * ".COLOR_BRIGHT."Crypt/Decrypt".COLOR_RESET." 'RSA public & private key' via cookbook: ".COLOR_BRIGHT."chef-vault".COLOR_RESET."
  * ".COLOR_BRIGHT."Openssh".COLOR_RESET."       'RSA openssh public key'   via cookbook: ".COLOR_BRIGHT."chef-vault".COLOR_RESET."

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a ACTION [-h] [-y] arguments

  -w   ".COLOR_GREEN."Forget all these complicated arguments! Just type -w to run 'Wizard' mode (Recommended)".COLOR_RESET."

  -a   One of the following actions
         list        => List certificates stored in Chef
         details     => Show details for certificate stored in Chef server
         create      => Creates a new 'x509 certificate & key' or 'RSA public & private key' or 'RSA openssh public key'
         update      => Update admins and/or nodes permissions
         permissions => Rebuild all permissions for all certificates and rotate all encrypted data bag keys
         import      => Import a new x509 certificate/key or priv/pub key into Chef
         delete      => delete an existing x509 certificate/key or priv/pub key from Chef
         retrieve    => Retrieve certificates from Chef Vault
         status      => Show certificates status. (certs. to expire, pending signing, etc.)
         backup      => Backup all certificates, keys and certification chain certificates to a PGP encripted local archive file.
  -c   knife.rb (knife config file) [defaults to ~/.chef/knife.rb]
  -f   x509 certificate or RSA public key file to import
  -s   Chef search filter used to
  -d   Databag - Databag to be used with retrieve action
  -i   Item    - Databag item to be used with retrieve action
  -h   This help text

";
}

/**
 * Help list
 */
function help_list()
{
  global $argv;

  help_header();

  print "
  List all certificates stored in Chef data bags.

  Data bag ".COLOR_GREEN.DATABAG_X509.COLOR_RESET." => x509 certificates
  Data bag ".COLOR_GREEN.DATABAG_RSA.COLOR_RESET."     => RSA certificates

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a list

";
}

/**
 * Help details
 */
function help_details()
{
  global $argv;

  help_header();

  print "
  Show details for a specific certificate.

  [Use '-a list' to get data bag and data bag item names. Take note of the blue items]

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a details -d data_bag_name -i item_name

  -d  Data bag name
  -i  Data bag item name

";
}

/**
 * Help create
 */
function help_create()
{
  global $argv;

  help_header();

  print "
  Create certificates

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a create

  ".COLOR_YELLOW."Not implemented yet".COLOR_RESET."\n\n";
}

/**
 * Help update
 */
function help_update()
{
  global $argv;

  help_header();

  print "
  Update vault secrets for already existent primary keys.
  Add / Delete admins / nodes.

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a update

  ".COLOR_YELLOW."Not implemented yet".COLOR_RESET."\n\n";
}


/**
 * Help import
 */
function help_import()
{
  global $argv;

  help_header();

  print "
  Import new 'x509 certificate' or 'RSA public key' from the current directory
  You must have in the current directory:
    - x509 certificate in a file
    - Corresponding private key in a file
    - Optionally the certification chain certificate(s) in a file

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a import -f certificate_file_name

  -f  Certificate file name
  -y  Assume Yes to all questions

  Example:
          Import www.foo.com x509 certificate

          # ".basename($argv[0])." -a import -f www_foo_com.crt

";
}

/**
 * Help delete
 */
function help_delete()
{
  global $argv;

  help_header();

  print "
  Delete 'x509 certificate' or 'RSA public key'

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a delete

  ".COLOR_YELLOW."Not implemented yet".COLOR_RESET."\n\n";
}

/**
 * Help retrieve
 */
function help_retrieve()
{
  global $argv;

  help_header();

  print "
  Retrieve 'x509 certificate' or 'RSA public key' from Chef server

  [Use '-a list' to get data bag and data bag item names. Take note of the blue items]

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a retrieve -d data_bag_name -i item_name

  -d  Data bag name
  -i  Data bag item name

";
}

/**
 * Help permissions
 */
function help_permissions()
{
  global $argv;

  help_header();

  print "
  Rebuild permissions for certificates and rotate all encrypted data bag keys
  Use when adding/removing a new admin or node

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a permissions [-d data_bag_name -i item_name]

  -d  Data bag name (optional)
  -i  Data bag item name (optional)

  Pass -d & -i to Rebuild permissions in a specific item, or else all items will be changed

";
}

/**
 * Help backup
 */
function help_backup()
{
  global $argv;

  help_header();

  print "
  Backup all certificates, keys and certification chain certificates to a PGP encripted local archive file.

  Usage:
          ".basename($argv[0])." [-c knife.rb] -a backup

";
}

/**
 * Help status
 */
function help_status()
{
  global $argv;

  help_header();

  print "
  Create certificates

  ".COLOR_YELLOW."Not implemented yet".COLOR_RESET."\n\n";
}

/**
 * Check for valid private key
 */
function check_valid_private_key($private_key_file)
{
  $private_key_handler = openssl_pkey_get_private(file_get_contents($private_key_file));
  if($private_key_handler === FALSE)
  {
    return FALSE;
  }
  else
  {
    return TRUE;
  }
}

/**
 * Find private key corresponding to the passed public key in current directory
 */
function find_private_key($public_key_info)
{
  if ($handle = opendir('.'))
  {
    while (false !== ($entry = readdir($handle)))
    {
      if(!is_file($entry)){continue; }

      $PRIVATE_KEY_STRING = file_get_contents($entry);
      $private_key_handler = openssl_pkey_get_private($PRIVATE_KEY_STRING);

      if($private_key_handler == FALSE){continue;}

      $private_key_info = openssl_pkey_get_details($private_key_handler);

      if($private_key_info['rsa']['n'] == $public_key_info['rsa']['n'])
      {
        $found            = new stdClass();
        $found->file_name = $entry;
        $found->info      = $private_key_info;
        $found->pem       = $PRIVATE_KEY_STRING;
        return $found;
      }
    }
  }
  closedir($handle);
  return NULL;
}

/**
 * Find a certiticate issuer
 */
function find_issuer($issuer)
{
  if ($handle = opendir('.'))
  {
    while (($entry = readdir($handle)) !== FALSE)
    {
      if(!is_file($entry)){continue;}

      $issuer_string = file_get_contents($entry);
      $issuer_info = openssl_x509_parse($issuer_string);
      if($issuer_info == NULL) {continue;}

      if($issuer_info['subject'] == $issuer)
      {
        $lines = file($entry);
        foreach($lines as $line)
        {
          $pem[] = $line;
          if(trim($line) == '-----END CERTIFICATE-----'){break;}
        }
        $pem = implode($pem);

        $found = new stdClass();
        $found->file = $entry;
        $found->pem  = $pem;
        $found->x509_certificate_info = $issuer_info;

        $found->ca_type = CA_INTERMEDIATE;
        if(get_self_signed_status($found))
        {
          $found->ca_type = CA_ROOT;
        }

        return $found;
      }
    }
  }
  closedir($handle);
  return NULL;
}

/**
 * Split all x509 bundle certificates in current directory
 */
function split_bundles()
{
  static $filename_number = 0;

  if ($handle = opendir('.'))
  {
    while (($entry = readdir($handle)) !== FALSE)
    {
      if(!is_file($entry)){continue;}

      $issuer_string = file_get_contents($entry);
      $issuer_info = openssl_x509_parse($issuer_string);
      if($issuer_info == NULL) {continue;}

      $lines = file($entry);

      $pems = array();
      $pems_found = 0;
      foreach($lines as $line)
      {
        if(trim($line) == '-----BEGIN CERTIFICATE-----') {$pems_found++;}
        $pems[$pems_found][] = $line;
      }

      if($pems_found > 1)
      {
        foreach($pems as $pem)
        {
          $pem = implode($pem);
          $pem_file_name = "splitted_pem_{$filename_number}.pem.crt";
          file_put_contents($pem_file_name, $pem);
          $filename_number++;
        }
      }
    }
  }
  closedir($handle);
  return NULL;
}

/**
 * Delete all "splitted_pem_{$pem_num}.pem.crt" generated by this run
 */
function delete_splitted_pems()
{
  if ($handle = opendir('.'))
  {
    while (($entry = readdir($handle)) !== FALSE)
    {
      if( preg_match("/^splitted_pem_[0-9]*\.pem\.crt/", $entry))
      {
        unlink($entry);
      }
    }
  }
  closedir($handle);
}

/**
 * Get all CNs from the certificate
 */
function get_domains($certificate_info)
{
  $domains = array();
  if(isset($certificate_info['extensions']['subjectAltName']))
  {
    $domains = str_replace('DNS:', '', $certificate_info['extensions']['subjectAltName']);
    $domains = explode(',', $domains);
  }
  $domains = array_merge(array($certificate_info['subject']['CN']), $domains);
  $domains = array_map('trim', $domains);
  $domains = array_unique($domains);
  $domains = array_values($domains);

  return $domains;
}

/**
 * Load knife config file from ruby to php
 */
function load_knife_config($config_file)
{
  $knife_config_contents = file($config_file);

  foreach($knife_config_contents as $line)
  {
    $line = trim($line);
    $line = preg_replace('!\s+!', ' ', $line);

    if(empty($line)) { continue;}

    if(preg_match("/(.*)\s=\s(.*)/", $line, $matches) == 0)
    {
      preg_match("/(.*)\s(.*)/", $line, $matches);
    }

    $knife_config[trim($matches[1])] = trim($matches[2], "'");
  }

  if ( !preg_match("/\/organizations\/.*/", $knife_config['chef_server_url']))
  {
    error("You must add '/organizations/YOUR_ORGANIZATION_NAME' to your config file: '{$config_file}' parameter 'chef_server_url' ");
    exit(1);
  }

  return $knife_config;
}

/**
 * Check internet connection / Chef server reachability
 *
 */
function get_chef_server_reachability()
{
  global $CHEF_HANDLER, $KNIFE_CONFIG;
  $data = $CHEF_HANDLER->get('/users/'.$KNIFE_CONFIG['node_name']);

  if($data === FALSE)
  {
    return FALSE;
  }

  return TRUE;
}

/**
 * Get users that will be added to the vault (chef-vault)
 */
function get_admins()
{
  global $CHEF_HANDLER;

  $admins = array();
  $users = $CHEF_HANDLER->get('/data/admins_vault/users');
  sort($users->users);
  return $users->users;
}

/**
 * Check if user has permissions to do some operations in chef-certs
 */
function has_admin_permission()
{
  global $CHEF_HANDLER;
  global $KNIFE_CONFIG;

  $users = $CHEF_HANDLER->get('/groups/admins');
  $current_user = $KNIFE_CONFIG['node_name'];
  if (!in_array($current_user, (array)$users->users))
  {
    error('You authenticated successfully as '.$current_user.' but you are not authorized for this action');
  }
}

/**
 * Search Chef server for given search string and
 * Return nodes that correspond to search string
 *
 * @param string $search_query
 * @return array Node names returned by cehf server search
 */
function search_nodes($search_query)
{
  global $CHEF_HANDLER;

  if (empty($search_query))
  {
    return array();
  }

  $nodes = array();
  $nodes =     $data = $CHEF_HANDLER->api('/search/node', 'GET', array('q' => $search_query ));

  $to_return = array();
  foreach($nodes->rows as $node)
  {
    $to_return[] = $node->name;
  }
  sort($to_return);

  return $to_return;
}

/**
 * Prints Wizard header
 *
 */
function wizard_header()
{
  // clear screen
  array_map(create_function('$a', 'print chr($a);'), array(27, 91, 72, 27, 91, 50, 74));

  print "
  ".COLOR_BRIGHT."Chef-certs - Wizard mode".COLOR_RESET."
  ------------------------
";
}

/**
 * Run Wizard mode
 *
 */
function wizard()
{
  wizard_header();
  print "
    L => List stored 'x509 certificate & key' and 'RSA public & private key'

    P => Rebuild permissions for certificates and rotate all encrypted data bag keys (Use when adding/removing a new admin or node)

    I => Import a new 'x509 certificate & key' or a new 'RSA public & private key', overwrites if already exists

    R => Retrieve an existing 'x509 certificate & key' or a new 'RSA public & private key'

    B => Backup all certificates, keys and certification chain certificates to a PGP encripted local archive file.

Please choose an option: [L,P,I,R,B] ";

//    C => Creates a new 'x509 certificate & key' or 'RSA public & private key' or 'RSA openssh public key'
//
//    U => Update admins (edit chef-vault's admins with access to all certificates)
//
//    D => Delete an existing 'x509 certificate & key' or a new 'RSA public & private key'
//
//    S => Show certificates status. (certs. to expire, pending signing, etc.)
//
//Please choose an option: [L,C,U,E,P,I,D,R,B,S] ";

//  $valid_options = array('l', 'c', 'u', 'e', 'p', 'i', 'd', 'r', 'b', 's');
  $valid_options = array('l', 'p', 'i', 'r', 'b');
  switch(get_user_input($valid_options))
  {
    case 'l':
      print "\n\nListing stored certificates:\n";
      list_wizard();
    break;

    case 'c':
      print "\n\nCreate new certificate:\n";
      error('Not implemented.');
    break;

    case 'u':
      print "\n\nUpdate administrators permissions on all certificates:\n";
      error('Not implemented.');
    break;

    case 'p':
      print "\n\nRebuild permissions for certificates:\n";
      has_admin_permission();
      rebuild_permissions();
    break;

    case 'i':
      print "\n\nImport certificate from current directory:\n";
      has_admin_permission();
      import_wizard();
    break;

    case 'd':
      print "\n\nDelete certificate:\n";
      error('Not implemented.');
    break;

    case 'r':
      print "\n\nRetrieve certificate from Chef server:\n";
      retrieve_wizard();
    break;

    case 'b':
      print "\n\nBackup, dump all certificates into a PGP local encrypted archive.\n";
      backup();
      break;

    case 's':
      print "\n\nShow certificates status.\n";
      error('Not implemented.');
      break;

    default:
      error("Invalid option, please type the letter corresponding to the desired action.");
  }
}


/**
 * Get user input (a string)
 *
 */
function get_user_string($valid_options)
{
  $handle = fopen ("php://stdin","r");
  $input = fgets($handle);
  $input = trim($input);

  if(!preg_match($valid_options, $input, $matches))
  {
    print "\n";
    error("Invalid option.");
  }

  return $input;
}

/**
 * Get user input (a single character)
 *
 */
function get_user_input($valid_options)
{
  $handle = fopen ("php://stdin","r");
  $input = fgets($handle);

//   readline_callback_handler_install('', function() { });
//   while (true)
//   {
//     $read   = array(STDIN);
//     $write  = NULL;
//     $except = NULL;
//     $num_changed_streams = stream_select($read, $write, $except, 0);

//     if ($num_changed_streams && in_array(STDIN, $read))
//     {
//       $input = stream_get_contents(STDIN, 1);
//       break;
//     }
//   }
//   readline_callback_handler_remove();

  $input = strtolower(trim($input));
  if( $input == '' || !in_array($input, $valid_options))
  {
    print "\n";
    error("Invalid option.");
  }

  return $input;
}

/**
 * Finds all public certificates in current directory
 *
 */
function find_all_public_keys()
{
  $to_return = array();
  if ($handle = opendir('.'))
  {
    while (false !== ($entry = readdir($handle)))
    {
      if(!is_file($entry)){continue; }

      $STRING = file_get_contents($entry);
      $public_key_handler = openssl_pkey_get_public($STRING);

      if($public_key_handler == FALSE){continue;}

      $to_return[] = $entry;
    }
  }
  closedir($handle);
  return $to_return;
}

/**
 * Pretty Print arrays (hey ruby?)
 *
 */
function pp($variable)
{
  print "variable: " . print_r($variable, TRUE) . "\n";
}

/**
 * Return an array with public keys which have a corresponding
 * private key in current directory
 *
 */
function filter_usable_public_keys($public_keys)
{
  global $INPUT_FILE_TYPE;

  $to_return = array();
  foreach($public_keys as $current)
  {
    $CERTIFICATE_STRING = file_get_contents($current);
    $public_key_handler = openssl_pkey_get_public($CERTIFICATE_STRING);

    if ( $public_key_handler === FALSE ) {continue;}

    $public_key_info = openssl_pkey_get_details($public_key_handler);

    if( ($private_key = find_private_key($public_key_info)) !== NULL )
    {
      $INPUT_FILE_TYPE = TYPE_X509;

      $x509_certificate_info = @openssl_x509_parse($CERTIFICATE_STRING);
      if($x509_certificate_info === FALSE)
      {
        $INPUT_FILE_TYPE = TYPE_RSA;
      }

      $found = new stdClass();
      $found->public_key_file       = $current;
      $found->private_key_file      = $private_key->file_name;
      $found->private_key_info      = $private_key->info;
      $found->public_key_info       = $public_key_info;
      $found->private_key_pem       = $private_key->pem;

      if ($INPUT_FILE_TYPE == TYPE_X509)
      {
        openssl_x509_export($CERTIFICATE_STRING, $pem);
        $found->x509_certificate_info = $x509_certificate_info;
        $found->x509_certificate_pem  = $pem;
      }

      $to_return[] = $found;
    }
  }

  return $to_return;
}

/**
 * Print error message and exit
 *
 */
function error($message)
{
  print "\n".COLOR_RED."Error:".COLOR_RESET." {$message}\n\n";
  exit(1);
}


/**
 * Get certification chain certificates for a certificate
 *
 */
function get_certification_chain($certificate)
{
  $CERTIFICATE_CHAIN = array();

  $current_certificate                        = new stdClass();
  $current_certificate->file                  = $certificate->public_key_file;
  $current_certificate->pem                   = $certificate->x509_certificate_pem;
  $current_certificate->x509_certificate_info = $certificate->x509_certificate_info;
  $current_certificate->ca_type               = CA_INTERMEDIATE;

  $old_certificate = NULL;
  while(($current_certificate = @find_issuer($current_certificate->x509_certificate_info['issuer'])) !== NULL)
  {
    if ($current_certificate === NULL)
    {
      continue;
    }

//     if( get_self_signed_status($current_certificate))
//     {
//       $current_certificate->ca_type = CA_ROOT;
//     }

    if($old_certificate == $current_certificate)
    {
      break;
    }
    $old_certificate = $current_certificate;

    $CERTIFICATE_CHAIN[] = $current_certificate;
  }

  if (isset($CERTIFICATE_CHAIN) && sizeof($CERTIFICATE_CHAIN) > 0)
  {
    return $CERTIFICATE_CHAIN;
  }

  return array();
}


/**
 * Determines if certificate is self-signed
 *
 */
function get_self_signed_status($certificate)
{
  $self_sigened_status = FALSE;
  if ($certificate->x509_certificate_info['subject'] == $certificate->x509_certificate_info['issuer'] )
  {
    $self_sigened_status = TRUE;
    unset($certificate->certification_chain_pem);
  }
  return $self_sigened_status;
}

/**
 * get private key data
 *
 */
function get_private_key_data($certificate)
{
  return array(
    "id"      => $certificate->private_key_id,
    "content" => $certificate->private_key_pem,
  );

}

/**
 * get rsa public key data
 *
 */
function get_rsa_public_key_data($certificate)
{
  $cert_data = array(
    "id"                   => $certificate->certificate_id,
    "public_key_filename"  => $certificate->public_key_file,
    "private_key_id"       => $certificate->private_key_id,
    "private_key_filename" => $certificate->private_key_file,
    'content'              => $certificate->public_key_info['key'],
  );

  return $cert_data;
}

/**
 * get x509 certificate data
 *
 */
function get_x509_certificate_data($certificate)
{
  $cert_data = array(
    "id"             => $certificate->certificate_id,
    "private_key_id" => $certificate->private_key_id,
  );

  if(isset($certificate->x509_certificate_info['name']))             { $cert_data["name"]                 = $certificate->x509_certificate_info['name'];                                      }
  if(isset($certificate->x509_certificate_info['subject']['C']))     { $cert_data["country"]              = $certificate->x509_certificate_info['subject']['C'];                              }
  if(isset($certificate->x509_certificate_info['subject']['ST']))    { $cert_data["state"]                = $certificate->x509_certificate_info['subject']['ST'];                             }
  if(isset($certificate->x509_certificate_info['subject']['L']))     { $cert_data["city"]                 = $certificate->x509_certificate_info['subject']['L'];                              }
  if(isset($certificate->x509_certificate_info['subject']['O']))     { $cert_data["organization"]         = $certificate->x509_certificate_info['subject']['O'];                              }
  if(isset($certificate->x509_certificate_info['subject']['OU']))    { $cert_data["department"]           = $certificate->x509_certificate_info['subject']['OU'];                             }
  if(isset($certificate->x509_certificate_info['subject']['CN']))    { $cert_data["cn"]                   = $certificate->x509_certificate_info['subject']['CN'];                             }
  if(isset($certificate->x509_certificate_info['hash']))             { $cert_data["hash"]                 = $certificate->x509_certificate_info['hash'];                                      }
  if(isset($certificate->x509_certificate_info['issuer']))           { $cert_data["issuer"]               = $certificate->x509_certificate_info['issuer'];                                    }
  if(isset($certificate->x509_certificate_info['serialNumber']))     { $cert_data["serial"]               = $certificate->x509_certificate_info['serialNumber'];                              }
  if(isset($certificate->x509_certificate_info['validFrom_time_t'])) { $cert_data["valid_from"]           = date('j F Y H:i:s (T)', $certificate->x509_certificate_info['validFrom_time_t']); }
  if(isset($certificate->x509_certificate_info['validTo_time_t']))   { $cert_data["valid_to"]             = date('j F Y H:i:s (T)', $certificate->x509_certificate_info['validTo_time_t']);   }
  if(isset($certificate->x509_certificate_info['validFrom_time_t'])) { $cert_data["valid_from_timestamp"] = $certificate->x509_certificate_info['validFrom_time_t'];                          }
  if(isset($certificate->x509_certificate_info['validTo_time_t']))   { $cert_data["valid_to_timestamp"]   = $certificate->x509_certificate_info['validTo_time_t'];                            }
  if(isset($certificate->domains))                                   { $cert_data["domains"]              = $certificate->domains;                                                            }

  $cert_data['self_signed'] = $certificate->self_signed;

  $cert_data['key_size'] = $certificate->private_key_info['bits'];

  $x509 = new File_X509();
  $cert = @$x509->loadX509($certificate->x509_certificate_pem);
  $cert_data['signature_algorithm'] = $cert['signatureAlgorithm']['algorithm'];

  if(isset($certificate->x509_certificate_info['extensions']['subjectAltName']))
  {
    $cert_data['subject_alt_name'] =  $certificate->x509_certificate_info['extensions']['subjectAltName'];
  }

  $cert_data['content'] = $certificate->x509_certificate_pem;

  if(isset($certificate->certification_chain_pem))
  {
    $cert_data['certification_chain'] = $certificate->certification_chain_pem;
  }

  return $cert_data;
}

/**
 * Get default knife.rb config file
 *
 */
function get_default_knife_config_file()
{
  global $_SERVER;
  $KNIFE_CONFIG_FILE = "{$_SERVER['HOME']}/.chef/knife.rb";
  return $KNIFE_CONFIG_FILE;
}

/**
 * Return an initialized Chef handler
 *
 */
function get_chef_handler()
{
  global $KNIFE_CONFIG;

  $chef = new Jenssegers\Chef\Chef($KNIFE_CONFIG['chef_server_url'], $KNIFE_CONFIG['node_name'], $KNIFE_CONFIG['client_key'], "12.0.1", TRUE);
  return $chef;
}

/**
 * Send Private Key to Chef
 * Create encripted data bag and its Vault
 *
 * @param string $certificate Certificate Object
 *
 */
function send_private_key_to_chef($certificate)
{
  global $KNIFE_CONFIG;
  global $INPUT_FILE_TYPE;
  global $CHEF_HANDLER;
  global $CHEF_ADMINS;
//  global $SEARCH_QUERY;

  switch ($INPUT_FILE_TYPE)
  {
    case TYPE_X509: $databag = DATABAG_X509; break;
    case TYPE_RSA:  $databag = DATABAG_RSA;  break;
    case TYPE_SSH:  $databag = DATABAG_SSH;  break;
  }

  $vault_verb = 'update';
  try
  {
    $resp = $CHEF_HANDLER->get("/data/{$databag}/{$certificate->private_key_id}");
  }
  catch (Exception $e)
  {
    $vault_verb = 'create';
  }

  // create secret for private_ke's encrypted databag
  $secret = base64_encode(openssl_random_pseudo_bytes(128));

  // encrypt encrypted databag using secret
  $private_key_encripted_data_bag_data = array(
    'id'      => $certificate->private_key_id,
    'content' => $CHEF_HANDLER->encrypt($certificate->private_key_pem, $secret),
    );

  // store private_key's encrypted databag
  try
  {
    $resp = $CHEF_HANDLER->delete("/data/{$databag}/{$certificate->private_key_id}");
  }
  catch (Exception $e)
  {
  }
  try
  {
    $resp = $CHEF_HANDLER->post("/data/{$databag}", $private_key_encripted_data_bag_data);
  }
  catch (Exception $e)
  {
  }

  $vault_id = "{$certificate->private_key_id}_keys";
  send_vault_to_chef($databag, $vault_id, $secret);

  print " - Private key uploaded into chef data bag/item: ".COLOR_BLUE.$databag.COLOR_RESET." / ".COLOR_GREEN.$certificate->private_key_id.COLOR_RESET."\n";
}

/**
 * Send vault to chef
 *
 * @param string $databag  Chef databag
 * @param string $vault_id Chef Vault item
 * @param string $secret   Vault secret
 *
 */
function send_vault_to_chef($databag, $vault_id, $secret)
{
  global $CHEF_HANDLER;

  // create vault (chef-vault)
  $vault_data = vault_data($vault_id, $secret);

  // store vault
  try
  {
    $resp = $CHEF_HANDLER->delete("/data/{$databag}/{$vault_id}");
  }
  catch (Exception $e)
  {
  }

  try
  {
    $resp = $CHEF_HANDLER->post("/data/{$databag}", $vault_data);
  }
  catch (Exception $e)
  {
  }
}

/**
 * Send x509 certificate to chef
 *
 */
function send_x509_certificate_to_chef($certificate)
{
  global $KNIFE_CONFIG;
  global $INPUT_FILE_TYPE;
  global $CHEF_HANDLER;

  switch ($INPUT_FILE_TYPE)
  {
    case TYPE_X509: $databag = DATABAG_X509; break;
    case TYPE_RSA:  $databag = DATABAG_RSA;  break;
    case TYPE_SSH:  $databag = DATABAG_SSH;  break;
  }

  try
  {
    $resp = $CHEF_HANDLER->delete("/data/{$databag}/{$certificate->certificate_id}");
  }
  catch (Exception $e)
  {
  }

  try
  {
    $resp = $CHEF_HANDLER->post("/data/{$databag}", $certificate->x509_certificate_data);
  }
  catch (Exception $e)
  {
  }

  print "\n - x509 Certificate uploaded into chef data bag/item: ".COLOR_BLUE.$databag.COLOR_RESET." / ".COLOR_GREEN.$certificate->certificate_id.COLOR_RESET."\n";
//  print "=> {$KNIFE_CONFIG['chef_server_url']}/databags/{$databag}/databag_items/{$certificate->certificate_id}\n";
  print "\n";
}


/**
 * Send RSA public key to chef server
 *
 */
function send_rsa_public_key_to_chef($certificate)
{
  global $KNIFE_CONFIG;
  global $INPUT_FILE_TYPE;
  global $CHEF_HANDLER;

  switch ($INPUT_FILE_TYPE)
  {
    case TYPE_X509: $databag = DATABAG_X509; break;
    case TYPE_RSA:  $databag = DATABAG_RSA;  break;
    case TYPE_SSH:  $databag = DATABAG_SSH;  break;
  }

#@TODO: usar get para ver se existe, e entao usar put ou post
  try
  {
    $resp = $CHEF_HANDLER->delete("/data/{$databag}/{$certificate->certificate_id}");
  }
  catch (Exception $e)
  {
  }

  try
  {
    $resp = $CHEF_HANDLER->post("/data/{$databag}", $certificate->public_key_data);
  }
  catch (Exception $e)
  {
  }

  print "\n - RSA Public Key   uploaded into chef data bag/item: ".COLOR_BLUE.$databag.COLOR_RESET." / ".COLOR_GREEN.$certificate->certificate_id.COLOR_RESET."\n";
//  print "=> {$KNIFE_CONFIG['chef_server_url']}/databags/{$databag}/databag_items/{$certificate->certificate_id}\n";
  print "\n";
}

/**
 * Check if certificate is expired
 *
 */

function check_valid_date($certificate)
{
  $now = time();

  return (($now >= $certificate->x509_certificate_info['validFrom_time_t']) && ($now <= $certificate->x509_certificate_info['validTo_time_t']));
}

/**
 * Wizard to import certificates into chef server data bag
 *
 */
function import_wizard()
{
  global $INPUT_FILE_TYPE;
  global $SEARCH_QUERY;

  $public_keys = find_all_public_keys();

  $usable_public_keys = filter_usable_public_keys($public_keys);

  if(sizeof($usable_public_keys) == 0)
  {
    error("No ".COLOR_BRIGHT."unencripted".COLOR_RESET." 'x509 certificates' or 'RSA public keys' with corresponding private key found in current directory.");
  }

  print "
Found the following items in current directory:

";
//  Found the following 'x509 certificates' or 'RSA public keys' with corresponding private key in current directory:

  foreach($usable_public_keys as $index => $public_key)
  {
    if ($INPUT_FILE_TYPE == TYPE_X509) { print( "     {$index} => {$public_key->x509_certificate_info['subject']['CN']}\n" );}
    if ($INPUT_FILE_TYPE == TYPE_RSA)  { print( "     {$index} => {$public_key->public_key_file}\n" ); }
  }

  print "
Please choose a certificate: ";

  $valid_options = array_keys($usable_public_keys);
  $user_input = get_user_input($valid_options);
  $certificate = $usable_public_keys[$user_input];

  if ($INPUT_FILE_TYPE == TYPE_X509) { $cert_name = $public_key->x509_certificate_info['subject']['CN']; }
  if ($INPUT_FILE_TYPE == TYPE_RSA)  { $cert_name = $public_key->public_key_file; }
  print "\nCertificate: ".COLOR_BRIGHT.$cert_name.COLOR_RESET."\n";

  set_data_bag_items_names($certificate);

  $SEARCH_QUERY = get_vault_search_query($certificate->vault_id);

//  print "\n\nAnalysing certificate.\n";
  import_certificate($certificate);
}

/**
 * Perform a search in chef, in the index passed as parameter
 *
 */
function chef_search($index, $query_string)
{
  global $CHEF_HANDLER;

  $node = array();
  try
  {
    $node = $CHEF_HANDLER->api('/search/'.$index, 'GET', array('q' => $query_string ));
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($node) == 0 )
  {
    return NULL;
  }
  return $node;
}

/**
 * Get a databag from chef
 *
 * @param string $databag Data bag name
 * @param string $item Item name
 *
 * @return array data bag data as returned from Chef server
 *
 */
function chef_get_data_bag_item($databag, $item)
{
  global $CHEF_HANDLER;

  try
  {
    $data = $CHEF_HANDLER->get("/data/{$databag}/{$item}");
  }
  catch ( Exception $e )
  {
  }
  if(isset($data) == 0 )
  {
    return array();
  }
  return $data;
}

/**
 * Get search_query from a vault
 *
 * @param string $vault_id
 *
 * @return array
 *
 */
function get_vault_search_query($vault_id)
{
  global $INPUT_FILE_TYPE;

  // procurar o vault, se existe, pegar o search_query
  if ($INPUT_FILE_TYPE == TYPE_X509) { $data_bag = DATABAG_X509; }
  if ($INPUT_FILE_TYPE == TYPE_RSA)  { $data_bag = DATABAG_RSA;  }

  $current_search_query = NULL;
  $vault = chef_get_data_bag_item($data_bag, $vault_id);
  if(empty($vault))
  {
    return array();
  }
  else
  {
    $raw_search_query = explode(' OR ', $vault->search_query);
    foreach($raw_search_query as $current_search)
    {
      $current_search_query[] = trim($current_search);
    }

    return array_unique($current_search_query);
  }
}

/**
 * Assembly new search query when running wizard mode:
 *  - Get current vault search query if exists
 *  - Ask user for new search quey
 *  - Append to existing vault search query
 *
 * @param string $vault_id
 *
 * @return array new search query
 */
function assembly_search_query($vault_id)
{
  $to_return = array();

  // procurar o vault, se existe, pegar o search_query
  $current_search_query = get_vault_search_query($vault_id);

  // se já existe search query, exibe na tela
  if(!empty($current_search_query))
  {
    $current_search_query_string = implode(' OR ', $current_search_query);
    $current_nodes = search_nodes($current_search_query_string);
    print "\nCurrent search query      => ".COLOR_GREEN.$current_search_query_string.COLOR_RESET."\n";
    if(empty($current_nodes))
    {
      $nodes_with_access = "NONE";
    }
    else
    {
      $nodes_with_access = implode(COLOR_RESET.' - '.COLOR_GREEN, $current_nodes);
    }
    print "Current nodes with access => ".COLOR_GREEN.$nodes_with_access.COLOR_RESET."\n";
  }
  else
  {
    return NULL;
  }

  if($current_search_query_string == '*:*')
  {
    print "\nCurrent search query is '*:*', cannot append more terms to it.\n";
    return $current_search_query;
  }

  print "\nEnter search query to add nodes: ";

  $user_input = get_user_string("/^[A-Za-z0-9:_-]*$/");

  $new_search_query = array();
  if(empty($current_search_query))
  {
    if(!empty($user_input))
    {
      $new_search_query[] = $user_input;
    }
  }
  else
  {
    if(empty($user_input))
    {
      $new_search_query = $current_search_query;
    }
    else
    {
      $current_search_query[] = $user_input;
      $new_search_query = array_unique($current_search_query);
    }
  }

  return $new_search_query;
}

/**
 * Manually import certificate
 *
 * @param string Certificate file name
 *
 */
function manual_import($CERTIFICATE_FILE)
{
  global $SEARCH_QUERY;

  $STRING = file_get_contents($CERTIFICATE_FILE);
  $public_key_handler = openssl_pkey_get_public($STRING);

  if($public_key_handler == FALSE)
  {
    error("File '{$CERTIFICATE_FILE}' is neither a 'rsa public key' or a 'x509 certificate'");
  }
  $public_keys = array( $CERTIFICATE_FILE );
  $usable_public_keys = filter_usable_public_keys($public_keys);
  $certificate = $usable_public_keys[0];

  set_data_bag_items_names($certificate);

  $current_search_query = get_vault_search_query($certificate->vault_id);
  $new_search_query = $current_search_query;
  if(!empty($SEARCH_QUERY))
  {
    $current_search_query_string = implode(' OR ', $current_search_query);
    if($current_search_query_string == '*:*')
    {
      print "\n".COLOR_YELLOW."Warning:".COLOR_RESET." Current Chef server search query for this certificate is '*:*', cannot append more terms to it. Ignoring parameter ".
             COLOR_BRIGHT."-s ".implode(' OR ', $SEARCH_QUERY).COLOR_RESET."\n";
    }
    else
    {
      $new_search_query = array_merge($current_search_query, $SEARCH_QUERY);
    }
  }
  $SEARCH_QUERY = array_unique($new_search_query);

  import_certificate($certificate);
}

/**
 * Set data bag items IDs
 *
 */
function set_data_bag_items_names($certificate)
{
  global $INPUT_FILE_TYPE;

  if ($INPUT_FILE_TYPE == TYPE_X509)
  {
    $base_name = preg_replace(array("/ /", "/\*/", "/\./"), array("_", "wildcard", "_"), $certificate->x509_certificate_info['subject']['CN']);
    $certificate->private_key_id = "{$base_name}_key";
    $certificate->certificate_id = "{$base_name}_cert";
  }

  if ($INPUT_FILE_TYPE == TYPE_RSA)
  {
    $certificate->private_key_id = preg_replace(array("/ /", "/\*/", "/\./"), array("_", "wildcard", "_"), $certificate->private_key_file);
    $certificate->certificate_id = preg_replace(array("/ /", "/\*/", "/\./"), array("_", "wildcard", "_"), $certificate->public_key_file);
  }

  $certificate->vault_id = "{$certificate->private_key_id}_keys";
}

/**
 * finish import certificate
 *
 * @param mixed $certificate Certificate Object
 *
 */
function import_certificate($certificate)
{
  global $INPUT_FILE_TYPE;
  global $CHEF_NODES;
  global $CHEF_ADMINS;
  global $ASSUME_YES;
  global $SEARCH_QUERY;
  global $ADD_SEARCH_TERM;

  if ($INPUT_FILE_TYPE == TYPE_X509)
  {
    split_bundles();
    $certificate->certification_chain = get_certification_chain($certificate);
    delete_splitted_pems();

    $chain_string = array();
    foreach($certificate->certification_chain as $current_chain_certificate)
    {
      // skip root ca in certification chain, it's not necessary
      if($current_chain_certificate->ca_type == CA_ROOT){continue;}

      $chain_string[] = $current_chain_certificate->pem;
    }
    $certificate->certification_chain_pem = implode("\n", $chain_string);
    $certificate->self_signed = get_self_signed_status($certificate);
    $certificate->domains = get_domains($certificate->x509_certificate_info);
    $certificate->valid_date =  check_valid_date($certificate);

    $certificate->x509_certificate_data = get_x509_certificate_data($certificate);

    $data_bag_name = DATABAG_X509;
  }

  if ($INPUT_FILE_TYPE == TYPE_RSA)
  {
    $certificate->public_key_data = get_rsa_public_key_data($certificate);
    $data_bag_name = DATABAG_RSA;
  }

  if($INPUT_FILE_TYPE == TYPE_X509) { display_x509_certificate_details($certificate); }
  if($INPUT_FILE_TYPE == TYPE_RSA)  { display_rsa_public_key_details($certificate);   }

  $ADD_SEARCH_TERM[] = "tags:cert\:". preg_replace("/_cert$/", '', $certificate->certificate_id);
  $SEARCH_QUERY = compose_search_query($data_bag_name, $certificate->certificate_id);

  $CHEF_ADMINS  = get_admins();
  $CHEF_NODES   = empty($SEARCH_QUERY) ? array() : search_nodes(implode(' OR ', $SEARCH_QUERY));

  print "\n";
  display_vault_users_and_nodes($certificate);

  if($ASSUME_YES)
  {
    store_data_in_chef_server($certificate);
  }
  else
  {
    print "
Do you wish to import this certificate into Chef server? [Y|N]";

    $valid_options = array('y', 'n');
    switch(get_user_input($valid_options))
    {
      case 'y':
        store_data_in_chef_server($certificate);
        break;

      default:
        print "\n";
        error("User Aborted");
    }
  }

// chef 12 nao demora a aparecere mais
//  print COLOR_BLUE."Notice:".COLOR_RESET." Please notice that it may take a couple of minutes for this certificate show up in searches.\n\n";
}

/**
 * store_cert / key into chef server
 *
 */
function store_data_in_chef_server($certificate)
{
  global $INPUT_FILE_TYPE;

  if ($INPUT_FILE_TYPE == TYPE_X509)
  {
    print "\n\nStoring x509 certificate into Chef server.\n";
    send_x509_certificate_to_chef($certificate);
  }

  if ($INPUT_FILE_TYPE == TYPE_RSA)
  {
    print "\n\nStoring RSA public key into Chef server.\n";
    send_rsa_public_key_to_chef($certificate);
  }

  print "Storing private key into Chef server.\n\n";
  send_private_key_to_chef($certificate);

  print "\n";
}

/**
 * Display rsa public key details on screen
 *
 */
function display_rsa_public_key_details($certificate)
{
  print "\n";
  print "RSA Private Key file  => {$certificate->private_key_file}\n";
  print "RSA Public  Key file  => {$certificate->public_key_file}\n";
}

/**
 * Get certificate display name
 *
 */
function get_display_name($subject)
{
  if(isset($subject['CN'])){ return $subject['CN'];}
  if(isset($subject['OU'])){ return $subject['OU'];}
  if(isset($subject['O'])) { return $subject['O'];}
  if(isset($subject['C'])) { return $subject['C'];}
  return '????';
}

/**
 * Display x509 certificate details on screen
 *
 */
function display_x509_certificate_details($certificate)
{
  print "\n";
  $inc = 0;

  print "Data bag            => ".COLOR_BLUE.DATABAG_X509.COLOR_RESET."\n";
  print "Data bag item       => ".COLOR_BLUE.$certificate->x509_certificate_data['id'].COLOR_RESET."\n\n";

  print "Certificate         => ".COLOR_BRIGHT."{$certificate->x509_certificate_info['subject']['CN']}".COLOR_RESET."\n";
  $inc++;

  $missing_ca = FALSE;
  if($certificate->self_signed === FALSE && sizeof($certificate->certification_chain) > 0)
  {
    // verify if we have the root ca in certification chain
    $has_root_ca = FALSE;
    foreach($certificate->certification_chain as $current_chain_certificate)
    {
      if($current_chain_certificate->ca_type == CA_ROOT)
      {
        $has_root_ca = TRUE;
      }
    }

    // print intermediates
    foreach($certificate->certification_chain as $current_chain_certificate)
    {
      if($current_chain_certificate->ca_type == CA_ROOT)
      {
        $chain_name = "Root CA        ";
      }
      else
      {
        $chain_name = "Intermediate CA";
      }
      $display_name = get_display_name($current_chain_certificate->x509_certificate_info['subject']);
      print "$chain_name     => " . sprintf("%s", str_repeat(' ', ($inc*2))) . '˪ ' . COLOR_BRIGHT . $display_name . COLOR_RESET . " ".COLOR_GREEN."(OK)".COLOR_RESET."\n";
      $inc++;
    }

    // print root CA
    if($has_root_ca == FALSE)
    {
      if(isset($certificate->certification_chain[0]))
      {
//        $count = count($certificate->certification_chain[0]);
        $count = count($certificate->certification_chain);
        $display_name = get_display_name($certificate->certification_chain[$count-1]->x509_certificate_info['issuer']);
      }
      else
      {
        $display_name = get_display_name($certificate->x509_certificate_info['issuer']);
      }
      print COLOR_YELLOW . "Missing CA".COLOR_RESET . "          => ".sprintf("%s", str_repeat(' ', ($inc*2))) . '˪ ' . COLOR_YELLOW.$display_name.COLOR_RESET." (RootCA is not required, if this is a RootCA then no worries)\n";
      $inc++;
      $missing_ca = TRUE;
    }
  }
  else
  {
    print COLOR_YELLOW . "Missing CA".COLOR_RESET . "          => ".sprintf("%s", str_repeat(' ', ($inc*2))) . '˪ ' .COLOR_YELLOW."-".COLOR_RESET." (No intermediate CA found)\n";
  }

  print "\n";

  if($certificate->self_signed === TRUE)
  {
    print COLOR_YELLOW."Self-Signed Certificate".COLOR_RESET."\n\n";
  }

//  print "All domains in this certificare:\n";
  $domain_number = 1;
  foreach($certificate->domains as $domain)
  {
    printf( "Domain #%  3d         => %s%s%s\n", $domain_number, COLOR_BRIGHT, $domain, COLOR_RESET);
    $domain_number++;
  }
  print "\n";

  print "Valid from          => ".COLOR_BRIGHT.$certificate->x509_certificate_data['valid_from'].COLOR_RESET."\n";
  print "Valid to            => ".COLOR_BRIGHT.$certificate->x509_certificate_data['valid_to'].COLOR_RESET."\n";
  if($certificate->valid_date === TRUE)
  {
    print "Status              => ".COLOR_GREEN."Valid".COLOR_RESET."\n";
  }
  else
  {
    print "Status              => ".COLOR_YELLOW."Expired".COLOR_RESET."\n";
    error("Certificate is expired.");
  }

  print "Serial              => ".COLOR_BRIGHT.$certificate->x509_certificate_info['serialNumber'].COLOR_RESET."\n";
  print "Signature Algorithm => ".COLOR_BRIGHT.$certificate->x509_certificate_data['signature_algorithm'].COLOR_RESET."\n";
  print "Private Key size    => ".COLOR_BRIGHT.$certificate->x509_certificate_data['key_size'].COLOR_RESET."\n";
}

/**
 * Display all users and nodes that will have access to the vault (chef-vault)
 *
 */
function display_vault_users_and_nodes($certificate)
{
  global $CHEF_ADMINS;
  global $CHEF_NODES;
  global $SEARCH_QUERY;
  global $KNIFE_CONFIG;

  $admins = implode(COLOR_RESET.' - '.COLOR_BRIGHT, $CHEF_ADMINS);
  print "\nAdmins with access  => ".COLOR_BRIGHT.$admins.COLOR_RESET."\n";

  $nodes = implode(COLOR_RESET.' - '.COLOR_BRIGHT, $CHEF_NODES);
//  print "\nSearch Query        => ".COLOR_BRIGHT.implode(' OR ', $SEARCH_QUERY).COLOR_RESET."\n";
  print "Nodes with access   => ";
  if(empty($CHEF_NODES))
  {
    print COLOR_RED."NONE".COLOR_RESET."\n";
//    print COLOR_YELLOW."Warning:".COLOR_RESET." No node(s) will be able to retrieve this certificate's primary key because search query does not return any node.\n";
  }
  else
  {
    print COLOR_BRIGHT.$nodes.COLOR_RESET."\n";
  }

  $tag_query = preg_replace('/tags\:|\\\|_cert$/', '', $SEARCH_QUERY);

  print "\nTag your servers using the following commands before use this certificate in a chef recipe:\n\n    ".
    COLOR_BRIGHT."knife tag create SERVER_NAME.DOMAIN \"";
  if (is_array($tag_query))
    print implode(' OR ', $tag_query);
  else
    print $tag_query;
  print COLOR_RESET."\"\n";

  print "    ".COLOR_BRIGHT."knife vault refresh ".DATABAG_X509." {$certificate->x509_certificate_data['private_key_id']}";
  print COLOR_RESET."\n";
}

/**
 * Get all items in databag
 *
 */
function get_databag_items_x509($query = '*:*')
{
  global $CHEF_HANDLER;

  $data = array();
  try
  {
    $data = $CHEF_HANDLER->api('/search/'.DATABAG_X509, 'GET', array('q' => $query ));
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($data) == 0 )
  {
    return array();
  }

  $databag_items = array();
  foreach($data->rows as $current_item)
  {
    $current_name = $current_item->raw_data->id;
    preg_match("/^(.*)(_keys$)/", $current_name, $matches);
    if( sizeof($matches) == 0 ) { continue; }
    $name = $matches[1];
    $ext  = $matches[2];
    $base_name = preg_replace("/_key$/", '', $name);
    $databag_items[$base_name]['vault'] = $current_item;
  }
//  asort($databag_items);

  foreach($databag_items as $item_key => $item_value)
  {
    foreach($data->rows as $current_item)
    {
      if($current_item->raw_data->id == "{$item_key}_cert")
      {
        $databag_items[$item_key]['cert'] = $current_item;
      }
      if($current_item->raw_data->id == "{$item_key}_key")
      {
        $databag_items[$item_key]['key'] = $current_item;
      }
    }
  }

  sort($databag_items);
  return $databag_items;
}

/**
 * Get all items in databag
 *
 */
function get_databag_items_rsa($query = '*:*')
{
  global $CHEF_HANDLER;

  $data = array();
  try
  {
    $data = $CHEF_HANDLER->api('/search/'.DATABAG_RSA, 'GET', array('q' => $query ));
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($data) == 0 )
  {
    return array();
  }

  // search all vaults and add them indexed by base name
  $databag_items = array();
  foreach($data->rows as $current_item)
  {
    $current_name = $current_item->raw_data->id;
    preg_match("/^(.*)(_keys$)/", $current_name, $matches);
    if( sizeof($matches) == 0 ) { continue; }
    $databag_items[$matches[1]]['vault'] = $current_item;

  }
//  asort($databag_items);

  // loop through all vault items and add pub / key
  foreach($databag_items as $item_key => $item_value)
  {
    foreach($data->rows as $current_item)
    {
      // skip vault items
      if($current_item->raw_data->id == "{$item_key}_keys"){continue;}

      // if public keys
      if(isset($current_item->raw_data->private_key_id))
      {
        $databag_items[$item_key]['cert'] = $current_item;
      }
      else
      {
        $databag_items[$item_key]['key']  = $current_item;
      }
    }
  }

  sort($databag_items);
  return $databag_items;
}

/**
 * Print databag items
 *
 */
function print_databag_items_x509($items, $header = TRUE)
{
  if($header)
  {
    $total_items = count($items);
    print "\nDatabag: ".COLOR_BLUE.DATABAG_X509.COLOR_RESET."\n\n";
    print "  Total items found: {$total_items}\n";
    print "\n";
  }

  foreach($items as $key => $current_item)
  {
    $key = sprintf("%  3d", $key);
    $cn = $current_item['cert']->raw_data->cn;
    $item_name = $current_item['cert']->raw_data->id;
    print_r("  {$key} => ".COLOR_BRIGHT."{$cn}".COLOR_RESET." (".COLOR_BLUE.$item_name.COLOR_RESET.")\n" );
  }

  print "\n";
}

/**
 * Print databag items
 *
 */
function print_databag_items_rsa($items, $header = TRUE)
{
  if($header)
  {
    $total_items = count($items);
    print "Databag: ".COLOR_BLUE.DATABAG_RSA.COLOR_RESET."\n\n";
    print "  Total items found: {$total_items}\n";
    print "\n";
  }

  foreach($items as $key => $current_item)
  {
    $key = sprintf("%  3d", $key);
    $key_name  = $current_item['key']->raw_data->id;
    $cert_name = $current_item['cert']->raw_data->id;
    print_r("  {$key} => ".COLOR_BRIGHT.$key_name.COLOR_RESET." / ".COLOR_BLUE.$cert_name.COLOR_RESET."\n" );
  }

  print "\n";
}

/**
 * Generate vault data (chef-vault) for private key
 *
 * @param string $vault_id
 * @param array $secret
 *
 * @return array key => userId or clientId, value => base64_encoded crypted secret
 */
function vault_data($vault_id, $secret)
{
  global $CHEF_ADMINS;
  global $CHEF_NODES;
  global $SEARCH_QUERY;

  $search_query = implode(' OR ', $SEARCH_QUERY);

  $CHEF_ADMINS = get_admins();
  $CHEF_NODES  = search_nodes($search_query);

  $to_return = array(
    'id'      => $vault_id,
    'admins'  => $CHEF_ADMINS,
    'clients' => $CHEF_NODES,
    'search_query' => $search_query,
  );

  $total_items = count($CHEF_ADMINS) + count($CHEF_NODES);
  $current_item = 0;
  $clients_with_error = array();

  foreach($CHEF_ADMINS as $admin)
  {
    $user_public_key = get_user_public_key($admin);
    if(is_null($user_public_key))
    {
      $clients_with_error[] = $admin;
      continue;
    }

    if(!openssl_public_encrypt($secret, $user_encrypted_secret_key, $user_public_key))
    {
      error("Could not encrypt secret vault for user '{$admin}' vault secret.");
    }

    $to_return[$admin] = base64_encode($user_encrypted_secret_key);

    $current_item++;
    printf("\rGenerating vault %s for private key %d/%d % 3d%% ", $vault_id, $current_item, $total_items, ($current_item/$total_items*100));
  }

  foreach($CHEF_NODES as $client)
  {
    $client_public_key  = get_client_public_key($client);
    if(is_null($client_public_key))
    {
      $clients_with_error[] = $client;
      continue;
    }

    if(!openssl_public_encrypt($secret, $client_encrypted_secret_key, $client_public_key))
    {
      error("Could not encrypt secret vault for node '{$client}' vault secret.");
    }

    $to_return[$client] = base64_encode($client_encrypted_secret_key);

    $current_item++;
    printf("\rGenerating vault %s for private key %d/%d % 3d%% ", $vault_id, $current_item, $total_items, ($current_item/$total_items*100));
  }

  print "\r                                                                                        \r";

  if(count($clients_with_error) > 0)
  {
    print COLOR_YELLOW."Warning:".COLOR_RESET." Could not retrieve public key from Chef server for the following clients (they'll not have access to this certificate):\n";
    print COLOR_YELLOW. implode(COLOR_RESET.' - '.COLOR_YELLOW, $clients_with_error) . COLOR_RESET."\n";
  }

  return $to_return;
}

/**
 * Find user public Key from chef server
 *
 * @param string User name as in chef server
 *
 * @return string Chef client RSA public key in PEM format
 */
function get_user_public_key($user_name)
{
  global $CHEF_HANDLER;

  $user = array();
  try
  {
    $user = $CHEF_HANDLER->get("/users/{$user_name}");
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($user) == 0 )
  {
//    print COLOR_YELLOW."\nWarning:".COLOR_RESET." Could not retrieve user '{$user_name}' public key from Chef server";
    return NULL;
  }

  return $user->public_key;
}


/**
 * Find client public Key from chef server
 *
 * @param string Client name as in chef server
 *
 * @return string Chef client RSA public key in PEM format
 */
function get_client_public_key($client_name)
{
  global $CHEF_HANDLER;

  $client = array();
  try
  {
    $client = $CHEF_HANDLER->get("/clients/{$client_name}");
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($client) == 0 )
  {
//    print COLOR_YELLOW."\nWarning:".COLOR_RESET." Could not retrieve client '{$client_name}' public key from Chef server\n";
    return NULL;
  }

  return $client->public_key;
}

/**
 * Get certificate's secret
 *
 * @param string $data_bag_name Data bag name
 * @param string $vault_name    Vault item id
 *
 * @return string Vault secret
 */
function get_certificate_secret_from_vault($data_bag_name, $vault_name)
{
  global $KNIFE_CONFIG;

  $user_name = $KNIFE_CONFIG['node_name'];

  // get current user's private key
  $user_private_key = file_get_contents($KNIFE_CONFIG['client_key']);

  $vault = chef_get_data_bag_item($data_bag_name, $vault_name);

  // get encrypted secret from certificate's vault
  $user_encrypted_secret_key = $vault->{$user_name};

  // decrypt secret
  $user_encrypted_secret_key = base64_decode($user_encrypted_secret_key);
  if(!openssl_private_decrypt($user_encrypted_secret_key, $secret, $user_private_key))
  {
    error("Could not decrypt user '{$user_name}' vault secret.");
  }

  return $secret;
}

/**
 * Decrypt private key
 *
 * @param string $data_bag_name data bag name
 * @param object $key private key databag object as returned from chef
 *
 * @return private key string in PEM format
 */
function decrypt_private_key($data_bag_name, $key)
{
  global $CHEF_HANDLER;

  $vault_name = "{$key->id}_keys";

  $secret = get_certificate_secret_from_vault($data_bag_name, $vault_name);

  // decrypt encrypted databag using secret
  $private_key = @$CHEF_HANDLER->decrypt($key->content, $secret);

  return $private_key;
}

/**
 * Retrieve a databag item
 *
 */
function manual_retrieve($data_bag_name, $data_bag_item)
{
  switch($data_bag_name)
  {
    case DATABAG_X509: manual_retrieve_x509($data_bag_name, $data_bag_item); break;
    case DATABAG_RSA:  manual_retrieve_rsa($data_bag_name, $data_bag_item); break;
  }
}

/**
 * Retrieve a databag item x509
 *
 */
function manual_retrieve_x509($data_bag_name, $data_bag_item)
{
  global $CHEF_HANDLER;

  $base_name       = preg_replace("/_cert$/", '', $data_bag_item);

  $cert_name       = "{$base_name}_cert";
  $cert_filename  = "x509/{$base_name}.crt.pem";

  $chain_filename = "x509/{$base_name}.chain.pem";

  $key_name        = "{$base_name}_key";
  $key_filename   = "x509/{$base_name}.key.pem";

  $cert = chef_get_data_bag_item($data_bag_name, $cert_name);
  if(empty($cert))
  {
    error("Could not retrieve Certificate");
  }

  $key = chef_get_data_bag_item($data_bag_name, $key_name);
  if(empty($key))
  {
    error("Could not retrieve Private Key");
  }

  if(!is_dir("x509")) { mkdir("x509", 0700); }

  file_put_contents($cert_filename,  $cert->content);
  chmod($cert_filename, 0400);

  if(isset($cert->certification_chain))
  {
    file_put_contents($chain_filename, $cert->certification_chain);
    chmod($chain_filename, 0400);
  }

  $private_key = decrypt_private_key($data_bag_name, $key);
  file_put_contents($key_filename, $private_key);
  chmod($key_filename, 0400);

  print "
    Certificate and Key successfuly retrieved.

    Private Key        : {$key_filename}
    Certificate        : {$cert_filename}\n";

  if(isset($cert->certification_chain))
  {
    print "    Certification Chain: {$chain_filename}\n";
  }

  print "\n\n";
}

/**
 * Retrieve a databag item rsa
 *
 */
function manual_retrieve_rsa($data_bag_name, $data_bag_item)
{
  global $CHEF_HANDLER;

  $cert = array();
  try
  {
    $cert = $CHEF_HANDLER->get("/data/{$data_bag_name}/{$data_bag_item}");
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($cert) == 0 )
  {
    error("Could not retrieve Certificate");
  }

  $key = array();
  try
  {
    $key = $CHEF_HANDLER->get("/data/{$data_bag_name}/{$cert->private_key_id}");
  }
  catch ( Exception $e )
  {
  }
  if(sizeof($key) == 0 )
  {
    error("Could not retrieve Private Key");
  }

  if(!is_dir("rsa")) {mkdir("rsa", 0700); }

  $public_key_filename = "rsa/{$cert->public_key_filename}";
  $private_key_filename = "rsa/{$cert->private_key_filename}";

  file_put_contents($public_key_filename,  $cert->content);
  chmod($public_key_filename, 0400);

  $private_key = decrypt_private_key($data_bag_name, $key);
  file_put_contents($private_key_filename, $private_key);
  chmod($private_key_filename, 0400);

  print "
    Public and Private Key successfuly retrieved.

    Private Key : {$private_key_filename}
    Public Key  : {$public_key_filename}

";
}

/**
 * select a certificate (wizard)
 *
 * @return object with data bag and item names
 */
function select_certificate()
{
  print "
Select certificate type :

  0 => x509 certificate
  1 => RSA public keys

";

  print "Please choose a certificate type: ";

  $valid_options = array(0, 1);
  $user_input = get_user_input($valid_options);

//  print "\n\n";

  switch($user_input)
  {
    case 0:
      $items = get_databag_items_x509();
      print_databag_items_x509($items, TRUE);
      $type = TYPE_X509;
    break;

    case 1:
      $items = get_databag_items_rsa();
      print_databag_items_rsa($items, TRUE);
      $type = TYPE_RSA;
    break;
  }

  print "Please choose a certificate: ";

  $valid_options = array_keys($items);
  $user_input = get_user_input($valid_options);

  print "\n";

  if(!is_numeric($user_input))
  {
    print "\n";
    error("Invalid option, please type the number corresponding to the desired certificate.");
  }

  $cert = new stdClass();
  $cert->databag = $items[$user_input]['cert']->data_bag;
  $cert->item    = $items[$user_input]['cert']->raw_data->id;
  $cert->type    = $type;

  return $cert;
}

/**
 * Wizard to retrieve certificates from chef server data bag
 *
 */
function retrieve_wizard()
{
  $cert = select_certificate();

  print "\n\nRetrieving {$cert->databag}.{$cert->item}\n";

//  show_stored_certificate_details($cert);

  manual_retrieve($cert->databag, $cert->item);
}

/**
 * List all stored certificates in chef
 *
 */
function list_wizard()
{
  global $INPUT_FILE_TYPE;

  $selected_cert = select_certificate();

  show_stored_certificate_details($selected_cert);
}

/**
 * List all stored certificates in chef
 *
 */
function manual_list()
{
  $items = get_databag_items_x509();
  print_databag_items_x509($items, TRUE);

  $items = get_databag_items_rsa();
  print_databag_items_rsa($items, TRUE);
}

/**
 * Show certificate details from command line parameters
 * Actually, it's Just a wrapper to call show_stored_certificate_details
 */
function manual_details($data_bag_name, $data_bag_item)
{
  $cert = new stdClass();
  $cert->databag = $data_bag_name;
  $cert->item    = $data_bag_item;

  if($data_bag_name == DATABAG_X509){ $cert->type = TYPE_X509; }
  if($data_bag_name == DATABAG_RSA) { $cert->type = TYPE_RSA;  }

  show_stored_certificate_details($cert);
}

/**
 * Show certificate details
 *
 */
function show_stored_certificate_details($cert)
{
  global $INPUT_FILE_TYPE;
  global $CHEF_ADMINS;
  global $CHEF_NODES;
  global $SEARCH_QUERY;

  $databag_item_cert = chef_get_data_bag_item($cert->databag, $cert->item);
  if(empty($databag_item_cert))
  {
    error("Data bag item ".COLOR_YELLOW.$cert->databag.COLOR_RESET." / ".COLOR_YELLOW.$cert->item.COLOR_RESET." has not been found.");
  }

  // get this certificate primary key's vault
  $databag_item_vault = chef_get_data_bag_item($cert->databag, "{$databag_item_cert->private_key_id}_keys");
  if(empty($databag_item_vault))
  {
    error("Vault ".COLOR_YELLOW.$cert->databag.COLOR_RESET." / ".COLOR_YELLOW."{$databag_item_cert->private_key_id}_keys has not been found.");
  }

  // assembly search query
  $SEARCH_QUERY = explode(' OR ', $databag_item_vault->search_query);

  // assembly admins from vault
  $admins_from_vault = $databag_item_vault->admins;
  sort($admins_from_vault);

  // get current admin list
  $current_admins_from_chef  = get_admins();
  sort($current_admins_from_chef);

  // compare if it's outdated, raise warning
  $diff = array_diff($current_admins_from_chef, $admins_from_vault);
  if(sizeof($diff) > 0 )
  {
    print "Warning: Admins list in this vault is outdated. Please update vault.\n";
  }

  $CHEF_ADMINS = $admins_from_vault;

  $INPUT_FILE_TYPE = $cert->type;
  $search_query = get_vault_search_query("{$databag_item_cert->private_key_id}_keys");
  $CHEF_NODES   = search_nodes(implode(' OR ', $search_query));

  if($cert->type == TYPE_X509)
  {
    $certificate = new stdClass();

    $certificate->certificate_id = $cert->databag;

    $certificate->x509_certificate_info  = @openssl_x509_parse($databag_item_cert->content);
    $certificate->x509_certificate_data  = (array) $databag_item_cert;

    $certificate->self_signed = $databag_item_cert->self_signed;
    $certificate->domains     = $databag_item_cert->domains;
    $certificate->valid_date  = check_valid_date($certificate);

    $previous_issuer = (array) $certificate->x509_certificate_info['issuer'];

    $certification_chain_issues = FALSE;
    $lines = explode("\n", $databag_item_cert->certification_chain);
    $pems = array();
    $pems_found = 0;
    foreach($lines as $line)
    {
      if(trim($line) == '-----BEGIN CERTIFICATE-----') {$pems_found++;}
      $pems[$pems_found][] = $line;
    }
    if($pems_found > 0)
    {
      // loop through all CAs to assembly certificat structure
      foreach($pems as $pem)
      {
        $pem = implode("\n", $pem);

        $found = new stdClass();
        $found->file = '-';
        $found->pem  = $pem;
        $found->x509_certificate_info = @openssl_x509_parse($pem);
        $found->ca_type               = CA_INTERMEDIATE;

        if($previous_issuer != $found->x509_certificate_info['subject'] )
        {
          $display_name =  get_display_name($found->x509_certificate_info['subject']);
          print COLOR_YELLOW."Warning:".COLOR_RESET." Certificate '".COLOR_BRIGHT.$display_name.COLOR_RESET."' is not required or misplaced at current chain position. (ignoring)\n";
          $certification_chain_issues = TRUE;
        }
        else
        {
        $certificate->certification_chain[] = $found;
        }
        $previous_issuer = $found->x509_certificate_info['issuer'];
      }
    }
    else
    {
      $certificate->certification_chain = array();
    }

    if( $certification_chain_issues == TRUE )
    {
      print COLOR_YELLOW."Warning:".COLOR_RESET." Certification chain has issues. ".COLOR_YELLOW."Re-import certificate to fix it.".COLOR_RESET."\n";
    }
    display_x509_certificate_details($certificate);
  }

  display_vault_users_and_nodes($certificate);

  print "\n";
}

/**
 * Show status for each certificate, looks for inconsistencies, pending issues, etc.
 *
 */
function manual_status()
{

  // loop through x509 certificates
  $x509_certificates = get_databag_items_x509();
  foreach($x509_certificates as $x509_certificate)
  {
//    $cert_id   = $x509_certificate['cert']->raw_data->id;
    $key_id  = $x509_certificate['cert']->raw_data->private_key_id;
    $key     = chef_get_data_bag_item(DATABAG_X509, $key_id);
//    $vault_id  = "{$x509_certificate['cert']->raw_data->private_key_id}_keys";

    //decrypt private key

// precisoo disso só para status?
// talvez para verificar se decripta
    $private_key_pem = decrypt_private_key(DATABAG_X509, $key);

    $private_key_handler = openssl_pkey_get_private($private_key_pem);
    $private_key_info = openssl_pkey_get_details($private_key_handler);

    // check private key less than 2048 bits
    if($private_key_info['bits'] < 2048)
    {
      print COLOR_YELLOW."Pritave Key is {$private_key_info->bits} bits. It must be at least 2048 bits\n";
    }

    // check certificate signature (md5, sha1, sha2, ...)

    // check certification chain signature (md5, sha1, sha2, ...)

    // check private key modulus X public key modulus

    // check about to expire certificates

    // check expired certificates

    // check CSR pending signatures

    // check certification chain

    // check admins access

    // check nodes access

    // check search query not returning any node

  }

  // loop through RSA certificates
  $rsa_certificates = get_databag_items_rsa();

}

/**
 * compose $SEARCH_QUERY from $ADD_SEARCH_TERM & $DEL_SEARCH_TERM
 *
 * @param string $data_bag_name Data bag name
 * @param string $data_bag_item Certificate item name
 *
 * @return array Search query
 */
function compose_search_query($data_bag_name, $data_bag_item)
{
  global $ADD_SEARCH_TERM;
  global $DEL_SEARCH_TERM;
  global $SEARCH_QUERY;

  $base_name  = preg_replace("/_cert$/", '', $data_bag_item);
  $vault_name = "{$base_name}_key_keys";

  $current_search_query_string = '';
  $current_search_query = array();

  $vault = chef_get_data_bag_item($data_bag_name, $vault_name);
  if(!empty($vault))
  {
    $current_search_query_string = $vault->search_query;
    $raw_search_query = explode(' OR ', $current_search_query_string);
    foreach($raw_search_query as $current_search)
    {
      $current_search_query[trim($current_search)] = trim($current_search);
    }
  }

  $new_search_query = $current_search_query;
  sort($current_search_query);

  if(is_string($DEL_SEARCH_TERM))
  {
    $DEL_SEARCH_TERM = array($DEL_SEARCH_TERM);
  }

  if(is_string($ADD_SEARCH_TERM))
  {
    $ADD_SEARCH_TERM = array($ADD_SEARCH_TERM);
  }

  if(!is_null($ADD_SEARCH_TERM))
  {
    foreach($ADD_SEARCH_TERM as $current_add_search_term)
    {
      $new_search_query[$current_add_search_term] = $current_add_search_term;
    }
    $new_search_query = array_filter($new_search_query);
  }

  if(!is_null($DEL_SEARCH_TERM))
  {
    foreach($DEL_SEARCH_TERM as $current_del_search_term)
    {
      unset($new_search_query[$current_del_search_term]);
    }
  }

  $new_search_query = array_unique($new_search_query);
  sort($new_search_query);

  return $new_search_query;
}

/**
 * Manual edit vault search query
 *
 * @param string data bag name
 * @param string item name
 *
 */
function manual_edit_search_query($data_bag_name, $data_bag_item)
{
  global $ADD_SEARCH_TERM;
  global $DEL_SEARCH_TERM;
  global $CHEF_ADMINS;
  global $SEARCH_QUERY;
  global $ASSUME_YES;

  $base_name  = preg_replace("/_cert$/", '', $data_bag_item);
  $vault_id = "{$base_name}_key_keys";

  print "\n\nEditing {$data_bag_name}.{$data_bag_item} vault nodes access\n";

  if(is_null($ADD_SEARCH_TERM) && is_null($DEL_SEARCH_TERM))
  {
    error("Nothing to add or delete, please run it agin with --add and/or --del parameters.");
  }

  if( in_array('*:*', $SEARCH_QUERY) && count($SEARCH_QUERY) > 1 )
  {
    error("Resulting search query contains '*:*' along with other terms, however '*:*' must be used alone.");
  }

  if(empty($SEARCH_QUERY))
  {
    error("New search query can not be empty.");
  }

  $current_search_query = get_vault_search_query($vault_id);
  if($current_search_query == $SEARCH_QUERY)
  {
    print "\nSearch query not changed, no update needed.\n\n";
    exit(0);
  }


  print "\n";

  if(!$ASSUME_YES)
  {
    print "
Do you wish to update search query for this certificate in Chef server? [Y|N]";

    $valid_options = array('y', 'n');
    switch(get_user_input($valid_options))
    {
      case 'y':
        break;

      default:
        print "\n";
        error("User Aborted");
    }
  }

  $secret = get_certificate_secret_from_vault($data_bag_name, $vault_id);
  send_vault_to_chef($data_bag_name, $vault_id, $secret);

  print "\n";

  $cert = new stdClass();
  $cert->databag = $data_bag_name;
  $cert->item    = $data_bag_item;
  if($data_bag_name == DATABAG_X509){ $cert->type = TYPE_X509; }
  if($data_bag_name == DATABAG_RSA) { $cert->type = TYPE_RSA;  }
  show_stored_certificate_details($cert);
}

/**
 * Rebuild all permissions for all certificates
 *
 */
function rebuild_permissions()
{
  global $INPUT_FILE_TYPE;
  global $ASSUME_YES;
  global $CHEF_ADMINS;
  global $CHEF_NODES;
  global $DATABAG_NAME;
  global $DATABAG_ITEM;

  print "\n".COLOR_YELLOW."ATTENTION:".COLOR_RESET." Never interrupt or abort this operation, it takes time and ".COLOR_RED."IS MANDATORY".COLOR_RESET." that it finishes once initiated.\n\n";
  if(!$ASSUME_YES)
  {
    print "Do you wish to rebuild certificates permissions? [Y|N]";

    $valid_options = array('y', 'n');
    switch(get_user_input($valid_options))
    {
      case 'y':
        break;

      default:
        print "\n";
        error("User Aborted");
    }
  }

  $rsa_items  = array();
  $cert_items = array();

  if(is_null($DATABAG_NAME) && is_null($DATABAG_ITEM))
  {
    $rsa_items  = get_databag_items_rsa();
    $cert_items = get_databag_items_x509();
  }
  else
  {
    $base_name = preg_replace("/_cert$/", '', $DATABAG_ITEM);

    if($DATABAG_NAME == DATABAG_RSA)
    {
      $rsa_items = get_databag_items_rsa("id:{$base_name}_*");
    }

    if($DATABAG_NAME == DATABAG_X509)
    {
      $cert_items = get_databag_items_x509("id:{$base_name}_*");
    }
  }

  $total_itens = count($rsa_items) + count($cert_items);
  $current_item = 0;

  $INPUT_FILE_TYPE = TYPE_RSA;
  foreach( $rsa_items as $cert_bundle )
  {
    rebuild_key($cert_bundle);

    $current_item++;
    printf("Total Progress: % 3d%%\r", ($current_item / $total_itens) * 100 );
  }

  $INPUT_FILE_TYPE = TYPE_X509;
  foreach( $cert_items as $cert_bundle )
  {
    rebuild_key($cert_bundle);

    $current_item++;
    printf("Total Progress: % 3d%%\r", ($current_item / $total_itens) * 100 );
  }

  print "\r                                                                                        \r\n";
}

/**
 * rebuild key, rotate secret, rebuild chef vault permissions
 *
 * @param mixed $cert_bundle Certificate object
 *
 */
function rebuild_key($cert_bundle)
{
  global $SEARCH_QUERY;

  $vault = $cert_bundle['vault']->raw_data;
  $key   = $cert_bundle['key']->raw_data;

  $SEARCH_QUERY = get_vault_search_query($vault->id);
  $secret = get_certificate_secret_from_vault($cert_bundle['vault']->data_bag, $vault->id);

  $certificate = new stdClass();
  $certificate->private_key_id = $key->id;
  $certificate->private_key_pem = decrypt_private_key($cert_bundle['key']->data_bag, $key);

  if (is_null($certificate->private_key_pem))
  {
    print COLOR_RED."Error: ".COLOR_RESET." Could not decrypt private key from Chef encrypted databag for ".COLOR_BRIGHT.$key->id.COLOR_RESET."\n        Re-Import this certificate from backup.\n\n";
    exit(1);
  }
  send_private_key_to_chef($certificate);
}

/**
 * Backup, dump all certificates into a PGP local encrypted archive.
 */
function backup()
{
  $items = array_merge(get_databag_items_rsa(), get_databag_items_x509());
  foreach($items as $data_bag_item)
  {
    manual_retrieve($data_bag_item['cert']->data_bag, $data_bag_item['cert']->raw_data->id);
  }
}
