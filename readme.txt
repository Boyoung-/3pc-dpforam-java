Three-Party DORAM Implementation

Setup:
$ sudo apt-get install ant
$ ant

Sample Run:
(shell1) $ scripts/eddie.sh &
(shell2) $ scripts/debbie.sh &
(shell3) $ scripts/charlie.sh &

Customize Parameters:
(shell1) $ scripts/eddie.sh -tau 3 -logN 12 -DBytes 4 &
(shell2) $ scripts/debbie.sh -tau 3 -logN 12 -DBytes 4 &
(shell3) $ scripts/charlie.sh -tau 3 -logN 12 -DBytes 4 &

Remote Servers:
(eddie) $ scripts/eddie.sh
(debbie) $ scripts/debbie.sh -eddie_ip [eddie_ip]
(charlie) $ scripts/charlie.sh -eddie_ip [eddie_ip] -debbie_ip [debbie_ip]