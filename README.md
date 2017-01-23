Chef-Certs
==========

Chef Certs utility provides a simple way to manage x509 certificates/keys or or RSA public/private keys using a Chef server as storage.
It will store public keys and certificates in a standard Chef data bag and private keys into a chef-vault (encrypted databag).
It doesn't recognizes DSA keys.

Installation
------------

####Automatic installation

We provide a Makefile so all you have to do is run:

    make install

####Manual installation

If the automatic method doesn't work for any reason, or even if you're felling brave, you can try the manual steps.

Install chef-client:
<http://www.getchef.com/chef/install/>

    curl -L https://www.opscode.com/chef/install.sh | sudo bash

Configure chef-client to access Chef server

    Create a ~/.chef/knife.rb config file
    Generate a user private key for your account in chef server and put it on ~/.chef
    Make sure ~/.chef/knife.rb points to yout Chef user private key

Install php-cli:
It's most likely you already have php-cli installed in your OS,
though you can install it using your OS package system
Make sure you have the following php extensions:

  - php openssl
  - php mcrypt

Install php composer:
(https://getcomposer.org/doc/00-intro.md#downloading-the-composer-executable)

    cd path/to/chef-certs
    curl -sS https://getcomposer.org/installer | php -- --filename=composer --install-dir=.

Install composer packages:

    cd path/to/chef-certs
    composer install

Optional: Link chef-certs to your PATH

    sudo ln -sf chef-certs.php /usr/bin/chef-certs
    # or
    sudo ln -sf chef-certs.php /usr/local/bin/chef-certs

Usage
-----

Easy way, run Wizard mode:

    chef-certs -w

Unattended way, command line parameters:

    chef-certs -a ACTION [-f CERTIFICATE_FILE]

Show command line help:

    chef-certs -h

Examples
--------

####Import a x509 certificate:
Create a directory and put all certificate files in it:
* RSA private key
* x509 certificate
* intermediate CA(s)
* RootCA

<b></b>

    cd path/to/certs
    chef-certs -a import -f foo.bar.com.crt.pem -s 'SEARCH'
    #SEARCH must be any Chef search query that returns nodes,
    #these nodes will be granted access to certificate being imported

####List all stored certificates:

    chef-certs -a list

####Show deatils of a stored certificate:
You must know the data bag name and data nag item name,
Use **chef-certs -a list** to copy data bag name & data bag item name (printed in blue)

    chef-certs -a details -d data_bag_name -i certificate_item_name

####Retrieve a certificate:
You must know the data bag name and data nag item name,
Use **chef-certs -a list** to copy data bag name & data bag item name (printed in blue)

    chef-certs -a retrieve -d data_bag_name -i certificate_item_name

Roadmap
-------

* Atualizar os admins / clients
   - Exibir o search_query e o resultado trazido com ele
   - permitir substituir ou altearar search query, sem que os nodes antigos percam acesso
* Listar status dos certificados
   - Exibir certificados que estão para expirar
   - Exibir certificados expirados
* Importar openssh public key?
   - carregando a priv e re-gerando uma pub?
* funcionar com rsa pub/priv e x509/priv no mesmo diretorio
* gerar certificado
   - gerar priv key -> armazenar no cef-vault
   - gerar CSR -> armazenar no chef data bag
   - gerar certificado temporário auto assinado (para os servicos nao bloquearam)
   - listar todos os CSRs pendentes (para conferencia, enviar para assinar, etc)
   - importar certificado assinado e descartar o auto assinado temporario
* renovacao de certificados
   - gerar nova Primary Key
   - Gerar CSR
* Mover certificados expirados para databag de certificados expirados
   - somente após o mesmo ser renovado
* Colocar CAs em databag separado
* Suportar formato PFX

