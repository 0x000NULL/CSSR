# The Magi

The Magi is a score scraper for the CyberPatriot Competition System. CyberPatriot has, in recent years, published a live score page with the current, real time score information from each competition round. This is useful, and beneficial for a variety of reasons, but it never includes the previous round scores, nor does it immediately make clear who will advance to subsequent rounds, and thus, to the National Finals competition. This script does just that.

Historical note: This is the next-generation version of the scraper that I operated during CyberPatriot 6. For historical purposes, I've uploaded [that script](https://github.com/nicatronTg/cp.shanked.me) to Github.

### Setting up

To set up The Magi, it's important to note that several things must be changed per round. Because the advancement rules change per season, and per round, calculating those who advance must be changed per round. In addition, minor tweaks to the HTML layout of the score engine and the actual score engine URL will also need to be accounted for before scraping will operate successfully.

Start by installing the required gems with Bundler: ````bundle install````.

Follow that up by making sure that you have MongoDB running somewhere. Specify the MongoDB location by running ````export MONGODB_URI=mongodb://HOST:PORT/DBNAME````. E.g. ````export MONGODB_URI=mongodb://localhost:27017/magi-r2````. 

Next, use the importer script to import a space delimited file with the previous round's open division and all service division scores. Typically, this is only required for Round 2 projections, as Round 1 and Round 2 are the only rounds that are combined to determine the outcome bracket. Some debug output is included to determine if a team addition fails. CyberPatriot has, on occasion, duplicated teams across divisions and in the same division during their result PDF releases, so this is important to check for. Run the script with ````ruby import.rb````.

At this point, it's time to begin testing the crawler. Run ````ruby continuous_crawl.rb```` to start the crawling process. The first step will attempt to download all of the score data from the official score engine. Next, it will begin stage two, the calculation stage. By default, this will calculate platinum bracket members, but for subsequent rounds, it should be trivial to change this logic to reflect the new advancement rules.

If the crawler is ingesting data successfully, launching the frontend should be trivial. Run ````rackup````, and the server will start listening on port 1290. To host this on somewhere other than your local pc, it would be wise to run it through a reverse proxy.

### Usage

The server has several routes:

* ````/rhs/```` redirects to the multi-team view page for all of Rangeview High School's teams.
* ````/team/:teamid/```` displays only that team's score.
* ````/teams/:teamid,teamid,teamid...```` displays several team scores at once.
* ````/:division```` supports either 'open' or 'all-service' and displays that division's top scores.
* ````/```` redirects to the open division score page.

### Improvements / Todo

1. Crawler should save the last run time and display it on the index, to spot errors earlier.
2. Index route should support choosing between open and all service division teams.
3. All service division has different advancement rules (and should be accounted for accordingly).

### Name

This script was named after The Magi, a set of three supercomputers in Neon Genesis Evangelion.

![](http://puu.sh/cR0km/d1cd9064c5.png)
