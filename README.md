## SandBox Framework


### Required Configuration

```
redef SandBox::mime_type_analysis += { SandBox::FILE_MSWORD , SandBox::FILE_PE , SandBox::FILE_PDF , SandBox::FILE_DOCX , SandBox::FILE_RAR};
redef SandBox::WILDFIRE_API_KEY = "<API-KEY>";
redef SandBox::WILDFIRE_SERVER = "IP";
redef SandBox::WILDFIRE_VERIFY_TLS = F;
```

### TIP

Add to local.zeek

```
redef FileExtract::default_limit = 10485760;
```