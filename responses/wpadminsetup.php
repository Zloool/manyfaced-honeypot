
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en" dir="ltr">
<head>
    <link rel="icon" href="../favicon.ico" type="image/x-icon" />
    <link rel="shortcut icon" href="../favicon.ico" type="image/x-icon" />
    <title>phpMyAdmin 2.11.9.4 setup</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />

    <script type="text/javascript">
    //<![CDATA[
    // show this window in top frame
    if (top != self) {
        window.top.location.href=location;
    }
    //]]>
    </script>
    <style type="text/css">
    /* message boxes: warning, error, stolen from original theme */
    div.notice {
        color: #000000;
        background-color: #FFFFDD;
    }
    h1.notice,
    div.notice {
        margin: 0.5em 0 0.5em 0;
        border: 0.1em solid #FFD700;
        background-image: url(.././themes/original/img/s_notice.png);
        background-repeat: no-repeat;
        background-position: 10px 50%;
        padding: 10px 10px 10px 36px;
    }
    div.notice h1 {
        border-bottom: 0.1em solid #FFD700;
        font-weight: bold;
        font-size: large;
        text-align: left;
        margin: 0 0 0.2em 0;
    }

    div.warning {
        color: #CC0000;
        background-color: #FFFFCC;
    }
    h1.warning,
    div.warning {
        margin: 0.5em 0 0.5em 0;
        border: 0.1em solid #CC0000;
        background-image: url(.././themes/original/img/s_warn.png);
        background-repeat: no-repeat;
        background-position: 10px 50%;
        padding: 10px 10px 10px 36px;
    }
    div.warning h1 {
        border-bottom: 0.1em solid #cc0000;
        font-weight: bold;
        text-align: left;
        font-size: large;
        margin: 0 0 0.2em 0;
    }

    div.error {
        background-color: #FFFFCC;
        color: #ff0000;
    }
    h1.error,
    div.error {
        margin: 0.5em 0 0.5em 0;
        border: 0.1em solid #ff0000;
        background-image: url(.././themes/original/img/s_error.png);
        background-repeat: no-repeat;
        background-position: 10px 50%;
        padding: 10px 10px 10px 36px;
    }
    div.error h1 {
        border-bottom: 0.1em solid #ff0000;
        font-weight: bold;
        text-align: left;
        font-size: large;
        margin: 0 0 0.2em 0;
    }

    fieldset.toolbar form.action {
        display: block;
        width: auto;
        clear: none;
        float: left;
        margin: 0;
        padding: 0;
        border-right: 1px solid black;
    }
    fieldset.toolbar form.action input, fieldset.toolbar form.action select {
        margin: 0.7em;
        padding: 0.1em;
    }

    fieldset.toolbar {
        display: block;
        width: 100%;
        background-color: #dddddd;
        padding: 0;
    }
    fieldset.optbox {
        padding: 0;
        background-color: #FFFFDD;
    }
    div.buttons, div.opts, fieldset.optbox p, fieldset.overview div.row {
        clear: both;
        padding: 0.5em;
        margin: 0;
        background-color: white;
    }
    div.opts, fieldset.optbox p, fieldset.overview div.row {
        border-bottom: 1px dotted black;
    }
    fieldset.overview {
        display: block;
        width: 100%;
        padding: 0;
    }
    fieldset.optbox p {
        background-color: #FFFFDD;
    }
    div.buttons {
        background-color: #dddddd;
    }
    div.buttons input {
        margin: 0 1em 0 1em;
    }
    div.buttons form {
        display: inline;
        margin: 0;
        padding: 0;
    }
    input.save {
        color: green;
        font-weight: bolder;
    }
    input.cancel {
        color: red;
        font-weight: bolder;
    }
    div.desc, label.desc, fieldset.overview div.desc {
        float: left;
        width: 27em;
        max-width: 60%;
    }
    code:before, code:after {
        content: '"';
    }
    span.doc {
        margin: 0 1em 0 1em;
    }
    span.doc a {
        margin: 0 0.1em 0 0.1em;
    }
    span.doc a img {
        border: none;
    }
    </style>
</head>

<body>
<h1>phpMyAdmin 2.11.9.4 setup</h1>
<div class="notice">
<h1>Welcome</h1>
You want to configure phpMyAdmin using web interface. Please note that this only allows basic setup, please read <a href="../Documentation.html#config">documentation</a> to see full description of all configuration directives.
</div>
<div class="warning">
<h1>Can not load or save configuration</h1>
Please create web server writable folder config in phpMyAdmin toplevel directory as described in <a href="../Documentation.html#setup_script">documentation</a>. Otherwise you will be only able to download or display it.
</div>
<div class="warning">
<h1>Not secure connection</h1>
You are not using secure connection, all data (including sensitive, like passwords) are transfered unencrypted! If your server is also configured to accept HTTPS request follow <a href="https://127.0.0.1/a2/scripts/setup.php">this link</a> to use secure connection.
</div>
<p>Available global actions (please note that these will delete any changes you could have done above):</p><fieldset class="toolbar"><legend>Servers</legend>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="addserver" /><input type="submit" value="Add" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
</fieldset>

<fieldset class="toolbar"><legend>Layout</legend>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_navigation" /><input type="submit" value="Navigation frame" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_tabs" /><input type="submit" value="Tabs" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_icons" /><input type="submit" value="Icons" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_browse" /><input type="submit" value="Browsing" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_edit" /><input type="submit" value="Editing" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="lay_window" /><input type="submit" value="Query window" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
</fieldset>

<fieldset class="toolbar"><legend>Features</legend>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_upload" /><input type="submit" value="Upload/Download" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_security" /><input type="submit" value="Security" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_manual" /><input type="submit" value="MySQL manual" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_charset" /><input type="submit" value="Charsets" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_extensions" /><input type="submit" value="Extensions" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="feat_relation" /><input type="submit" value="MIME/Relation/History" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
</fieldset>

<fieldset class="toolbar"><legend>Configuration</legend>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="main" /><input type="submit" value="Overview" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="display" /><input type="submit" value="Display" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="download" /><input type="submit" value="Download" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="save" /><input type="submit" value="Save" disabled="disabled" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="load" /><input type="submit" value="Load" disabled="disabled" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="clear" /><input type="submit" value="Clear" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="seteol" /><select name="neweol"><option value="unix" >UNIX/Linux (\n)</option><option value="dos"  selected="selected">DOS/Windows (\r\n)</option><option value="mac" >Macintosh (\r)</option>
        </select><input type="submit" value="Change end of line" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
</fieldset>

<fieldset class="toolbar"><legend>Other actions</legend>
<form class="action" method="post" action=""><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="action" value="versioncheck" /><input type="submit" value="Check for latest version" /><input type="hidden" name="configuration" value="a:1:{s:7:&quot;Servers&quot;;a:0:{}}" />
<input type="hidden" name="eoltype" value="dos" />
</form>
<form class="action" method="get" action="http://www.phpmyadmin.net/" target="_blank"><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="submit" value="Go to homepage" /></form>
<form class="action" method="get" action="https://sourceforge.net/donate/index.php" target="_blank"><input type="hidden" name="token" value="e4b8fadb50cc56de06a10ddd25abab7e" /><input type="hidden" name="group_id" value="23067" /><input type="submit" value="Donate to phpMyAdmin" /></form>
</fieldset>

</body></html>
