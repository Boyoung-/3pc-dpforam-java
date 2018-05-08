Three-Party DORAM Implementation

Setup:
$ sudo apt-get install ant
$ ant

Sample Run:
$ scripts/eddie.sh &
$ scripts/debbie.sh &
$ scripts/charlie.sh &

Customize Parameters:
$ scripts/eddie.sh -tau 3 -logN 12 -DBytes 4 &
$ scripts/debbie.sh -tau 3 -logN 12 -DBytes 4 &
$ scripts/charlie.sh -tau 3 -logN 12 -DBytes 4 &