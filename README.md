# PHP File Manager

A good solution for managing files and folders for developers who can't access their site over SSH or FTP.

![PHP File Manager](https://raw.github.com/alexantr/filemanager/master/phpfm.png)


## Requirements

- PHP 7 or higher.
- [Zip extension](http://php.net/manual/en/book.zip.php) for zip and unzip actions.
- Fileinfo, iconv and mbstring extensions are strongly recommended.

## How to use

Download ZIP with the latest version from the master branch.

Copy **filemanager.php** to your website folder and open it in a web browser
(e.g. http://yoursite/any_path/filemanager.php).

## Security

Default username/password: **admin**/**admin123**

**Warning! Please set your own username and password in `

$auth_users = array(
    'admin' => [
        'password_hash' => '$2y$10$YT6FJxHXVzPl4YZAuD.hBubAJ6/XE3vPWdrcLDCNQVR2nYpgTk9ym', // password: admin123

To enable or disable authentication set `$use_auth` to `true` or `false`.

*For better security enable HTTP Authentication in your web server.*

this version is more secure, because use PHP 7 or higher.

## License

This software is released under the MIT license.

Icons by [Yusuke Kamiyamane](http://p.yusukekamiyamane.com/).
