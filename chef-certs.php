<?php
/**
 * Imports a x509 cert/key pair into a chef-vault data bag
 * Imports a rsa   pub/key pair into a chef-vault data bag
 *
 * Alexandre Zia <alexandre@zia.com.br>
 */

/**
 * Set default timezone to UTC
 */
date_default_timezone_set('UTC');

/**
 * determine installation directory
 */
define('INSTALL_DIR', dirname(__FILE__));

/**
 * load library
 */
require_once INSTALL_DIR.'/lib/library.php';

/**
 * Load Chef api
 */
if(!is_dir(INSTALL_DIR.'/vendor'))
{
  error("Install & run composer in order to download dependencies. (make install)");
}
require_once INSTALL_DIR.'/vendor/autoload.php';
use Jenssegers\Chef\Chef;
include('File/X509.php');

/**
 * parse command line arguments
 */
parse_command_line_arguments();

/**
 * find knife config file
 */
if(is_null($KNIFE_CONFIG_FILE))
{
  $KNIFE_CONFIG_FILE = get_default_knife_config_file();
}
if(!is_file($KNIFE_CONFIG_FILE))
{
  error("Knife config file not found in ~/.chef/knife.rb");
  exit(1);
}

/**
 * Load knife config file
 */
$KNIFE_CONFIG = load_knife_config($KNIFE_CONFIG_FILE);

/**
 * Check if knife.rb points to an existent and valid RSA private key
 */
if(!is_file($KNIFE_CONFIG['client_key']))
{
  error("Private Key file not found. '{$KNIFE_CONFIG['client_key']}'");
}

if(!check_valid_private_key($KNIFE_CONFIG['client_key']))
{
  error("'{$KNIFE_CONFIG['client_key']}' is not a valid RSA pprivate Key");
}

/**
 * Get a chef server handler
 */
$CHEF_HANDLER = get_chef_handler();

/**
 * check chef server reachability
 */
print "\nChecking Chef server connectivity ... ";
if(!get_chef_server_reachability())
{
  error("Cannot connect to chef server. Check network connectivity or chef credentials.");
  exit(2);
}
print COLOR_GREEN."OK".COLOR_RESET."\n";

/**
 * If run wizard
 */
if(!is_null($RUN_WIZARD))
{
  wizard();
  exit(0);
}

/**
 * sanity checks
 */
if($ACTION == ACTION_IMPORT)
{
  if(empty($CERTIFICATE_FILE))
  {
    error ("Missing -f parameter.");
  }

  if(!is_file($CERTIFICATE_FILE))
  {
    error ("File '{$CERTIFICATE_FILE}' does not exists.");
  }
}

/**
 * no wizard, run by command line args
 */
switch($ACTION)
{
  case ACTION_LIST:
    print "\nListing stored certificates:\n";
    manual_list();
    break;

  case ACTION_DETAILS:
    print "\nShow certificate details:\n";

    if(!isset($DATABAG_NAME))
    {
      error ("Missing parameter -d");
    }
    if(!isset($DATABAG_ITEM))
    {
      error ("Missing parameter -i");
    }

    manual_details($DATABAG_NAME, $DATABAG_ITEM);
    break;

  case ACTION_CREATE:
    print "\nCreate new certificate:\n";
    error('Not implemented.');
    break;

  case ACTION_UPDATE:
    print "\nUpdate administrators permissions on all certificates:\n";
    error('Not implemented.');
    break;

  case ACTION_EDIT:
    print "\nEdit nodes access to a certificate vault:\n";

    if(!isset($DATABAG_NAME))
    {
      error ("Missing parameter -d");
    }
    if(!isset($DATABAG_ITEM))
    {
      error ("Missing parameter -i");
    }

    manual_edit_search_query($DATABAG_NAME, $DATABAG_ITEM);
    break;

  case ACTION_IMPORT:
   print "\nImport certificate from current directory:\n";

   if(!isset($CERTIFICATE_FILE))
   {
     error ("Import certificate requires parameter -f certificate_file");
   }

   manual_import($CERTIFICATE_FILE);
   break;

  case ACTION_DELETE:
    print "\nDelete certificate:\n";
    error('Not implemented.');
    break;

  case ACTION_RETRIEVE:
    print "\nRetrieve certificate from Chef server:\n";

    if(!isset($DATABAG_NAME))
    {
      error ("Missing parameter -d");
    }
    if(!isset($DATABAG_ITEM))
    {
      error ("Missing parameter -i");
    }

    manual_retrieve($DATABAG_NAME, $DATABAG_ITEM);
    break;

  case ACTION_STATUS:
    print "\nShow certificates status.\n";
    manual_status();
    break;

  case ACTION_BACKUP:
      print "\nBackup, dump all certificates into a PGP local encrypted archive.\n";
      backup();
      break;

  case ACTION_PERMISSIONS:
    print "\nRebuild all Permissions.\n";
    rebuild_permissions();
    break;

  default:
    error("Unknown Action");
    usage();
    exit(1);
}

exit(0);
