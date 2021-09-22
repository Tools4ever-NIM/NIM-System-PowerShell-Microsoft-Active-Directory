# NIM-Conn-System-PowerShell-Active-Directory


## Evaluate Automated Delete Date
```
let status = true;

let description = Users['description'];

if(description.includes('AUTOMATED - Delete After:'))
{
	description = description.replace('AUTOMATED - Delete After:','').trim();
  	try
    {
      let deleteDate = new Date(description);
      let todayDate = new Date();

      if(todayDate > deleteDate)
      {
       	status = false;
      }
      else
      {
      }
      
    }
    catch(e)
    {
    }
}

return status;
```
