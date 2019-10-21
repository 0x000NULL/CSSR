# CyberPatriot Team Monitor
The CyberPatriot Team Monitor provides an apparatus for filtering the
score report information available from the
[National Youth Cyber Defense Competition](https://uscyberpatriot.org).

This team monitor is configured for a group of teams in California which
is part of the West region.



## Design Needs
This CyberPatriot team monitor was developed based on the following
design needs for input sources, output modes, and utility use cases



### Data Model
This section identifies the data entity model for this utility. The
order of import for entities shall follow the rule that official
sources, when available, will be ingested before unofficial sources and
within those categories where static and dynamic information is
clearly identifiable a strict ordering of static then dynamic shall be
observed. Updates to the data model are otherwise performed in the order
that the sources are listed as inputs to the utility.

#### Loading Sources and the Melded Data Model
Sources can be loaded on-demand and cached for later reference
with a last-refreshed time used to determine when remote sources need to
be refreshed. Sources are cached in native format and may optionally be
pre-processed into another format such as CSV and JSON before being
processed for ingest. Failure to refresh a source falls back to any
local cached copies.

Synthetic data selectors are may be determined at the time of injest,
an example is importing score data that is already sorted into
rank-order from which rankings by division, division/state,
division/region, and globally can be synthesized.

When any source is refreshed a consistent source ordering is applied to
generate the melded data model, using cached data if necessary.

#### Applying Filters to the Data Model
Filter and output selectors are applied to the melded data model only
after sources have been cached.

#### Team Record
Currently stored as CSV containing an organizational header including
revision number and column headings followed by one or more rows
containing information for one team per row.

Team Records can be fabricated out of official registered team
information or from unofficial (team, regional or CoE organizer) sources
and augmented per fields supported by a data record version.

##### Team Record Keys

###### team_number
Common team number and identifier used to partially anonymize scoreboard
reports

###### city, state, zip_code
location information; `state` is the name of the State within the USA or
for locations outside of the USA the Country or Territory name is used

###### division
Exactly one selection from the set
`{ "Open", "All Service", "Middle School" }`

###### organization_name, organization_type, organization_notes
Name, type, and notes are free-form but is generally consistent within
the same organization

###### center_of_excellence
Listed affiliation with a regional CyberPatriot Center of Excellence

###### coach, coach_email
Name and point-of-contact email information for team Coach

###### team_name,team_memberX
Nickname created by the team members, and a listing of up to 6 team
members

##### Team Record V1
Header line is the following
```csv
#team_v0.1=team_number,state,division,organization_name,organization_type,organization_notes,center_of_excellence,city,zip_code,coach,coach_email,team_name,team_member1,team_member2,team_member3,team_member4,team_member5,team_member6

[optionally left blank]
organization_notes,center_of_excellence,city,zip_code,coach,coach_email,team_name,team_member1,team_member2,team_member3,team_member4,team_member5,team_member6,
```



### Input Sources
* Ingest official registered team info
(e.g. http://www.uscyberpatriot.org/Documents/CP-IX%20Current%20Registered%20Teams.pdf)
* Pull live competition round data from HTML at
http://scoreboard.uscyberpatriot.org
when available
* Ingest official score data published after each round at
https://www.uscyberpatriot.org/Documents/Scores
normally in Excel XML format
* (Optional) Pull data from third-party source HTML
(e.g. http://magi.jump.software/{all,open,all-service,ms})
* Structured data dump listings of team info, component scores, ranking
order, or predictive results

#### Official Registered Team Info (updated for CPIX 2016-2017)
This information cannot be readily used as the team entries do not
identify the team number used as a primary index into the remaining
data sets for this competition. However, this utility will standardize
the use of the fields identified in this resource to support ingest from
another source.
```
Data Model Mappings
-------------------
School/Org Type -> organization_type
Organization Name -> organization_name
Team Nickname -> team_name
COE Affiliation -> center_of_excellence
City -> city
State -> state
Zip Code -> zip_code
```

#### Official Score Data
Generally we will have to apply a mapping from the score document into
our data model in order to account for variation in published score data
column names and meanings.

The typical warnings about regex not being suitable for general parsing
of HTML/XML still apply but by applying some structure to our data and
focusing on a small subset of the entire HTML document we can filter out
just the pieces of interest quite readily. This is a good example of how
'knowing your data' enables efficient processing.
```bash
$ URI='https://www.uscyberpatriot.org/competition/current-competition/scores'
$ wget -O - ${URI} 2>/dev/null \
    | sed -e 's%\([\<]a href=\)\"%\^J^M\1%g' \
    | grep 'Documents/Scores' \
    | sed -e 's/" .*$//' -e 's/<a href=//'
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R2 Open Division.xlsx
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R2 All Service Division.xlsx
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R2 Middle School Division.xlsx
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R1 Open Division.xlsx
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R1 All Service Division.xlsx
https://www.uscyberpatriot.org/Documents/Scores/CP-IX R1 Middle School Division.xlsx
```



### Output Modes
* Plaintext, CSV, or JSON output when invoked at command-line
* HTML or JSON when accessed via web application



### Use Cases
Take input sources, an optional list of selectors to filter on (e.g.
team number, state, city, zipcode, region, division), and an optional
list of selectors to be included with output records.

Static and dynamic official sources can be included by brevity code
including an all-inclusive logical `all-official` source.

Filter and output selectors can also be specified by key or by using
preset output selector groupings (e.g. `standard-ranks`).

#### Command-Line Usage
Sources (including logical sources), filter selectors, output selectors,
and output formats are defined by command-line options.

#### Web Application Usage
Static and dynamic official sources are listed within the web
application and unofficial sources can be provided as URI or JSON as
part of the HTTP request with "type: source" attribute.

Filter selectors, output selectors, and output format are taken as
parameters using URI query syntax or as JSON in the HTTP request with
the 'type: filter' and 'type: output' parameters. Output format is given
as HTML, CSV, or JSON
