# NIM-Conn-System-PowerShell-Active-Directory

## Automated Deletion

### Example Filter
![image](https://user-images.githubusercontent.com/24281600/134387022-fd8ba2b2-cc22-466d-b954-605d3cdd93c7.png)

![image](https://user-images.githubusercontent.com/24281600/134387051-0ea9975b-86eb-44ce-98b6-4e34b36e46a0.png)

### Populate Automated Deletion Date
This script column sets up the automated deletion date so it can be populated in AD when the account is disabled
```
let daysInFuture = 365;

let description = 'AUTOMATED - Delete After: ';
let date = new Date();
date.setDate(date.getDate() + daysInFuture);
let year = date.getUTCFullYear();
let month = date.getUTCMonth()+1;
let day = date.getUTCDate();

if (day < 10) { day = '0' + day; }
if (month < 10) { month = '0' + month; }

let deleteDate = '' + year + '-' + month + '-' + day

description += deleteDate;
return description;
```

### Evaluate Automated Deletion Date
This script column is used to determine if Automated Delete Date is in the future. If in the future, then the result is true.


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
