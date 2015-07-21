#!/usr/bin/perl -w

use List::Util qw(min max);
use JSON;
use strict;

my %users = map { (shift @ARGV, { index => ($_) }) } 1..@ARGV;

my %colors = (1 => 'orange',
              2 => 'blue',
              3 => 'lightgreen',
              4 => 'purple',
              5 => 'darkgray',
              6 => 'pink',
              7 => 'white',
              8 => 'black');

my @records = ();
my %ips = ();
my $max_time;
my $min_time;

while (<>) {
    my $record = decode_json $_;
    my $user = $record->{user};
    next if !exists $users{$user};
    $users{$user}{max_time} = max $record->{timestamp}, ($users{$user}{max_time} // 0); 
    push @records, $record;
}

my $cutoff = 3600*8 + (sort map { $_->{max_time} } values %users)[-2];
@records = sort {
    $a->{timestamp} <=> $b->{timestamp}
} grep {
    $_->{timestamp} lt $cutoff;
} @records;

for my $record (@records) {
    $max_time //= $record->{timestamp};
    $min_time //= $record->{timestamp};

    if (!defined $ips{$record->{ip}}) {
        $ips{$record->{ip}} = 1 + scalar keys %ips;
    }

    $max_time = max $max_time, $record->{timestamp};
    $min_time = min $min_time, $record->{timestamp};
}

sub timestamp_to_y {
    return 50 + ($_[0] - $min_time) / 1800 * 12;
}

my $ip_width = 12 * (2 + scalar keys %users);

sub ip_to_x {
    return $_[0] * $ip_width;
}

sub draw_record {
    my ($record) = @_;
    my $user_offset = $users{$record->{user}}{index} * 12;
    my $x = $user_offset + ip_to_x $ips{$record->{ip}};
    my $y = timestamp_to_y $record->{timestamp};
    my $color = $colors{$users{$record->{user}}{index}};

    if ($record->{delay}) {
        $x += 4;
        print "  <rect x='$x' y='$y' width='3' height='10' fill='$color' stroke='black' stroke-width='1'/>\n";
    } else {
        print "  <rect x='$x' y='$y' width='10' height='10' fill='$color' stroke='black' stroke-width='1'/>\n";
    }
}

my $height = 50 + timestamp_to_y $max_time;
my $width = (2 + scalar keys %ips) * $ip_width;

print qq(<svg width='$width' height='$height' xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">);

for my $ip (values %ips) {
    my $x = ip_to_x $ip;
    my $color = ('#ffe', '#f0f0f0')[$ip % 2];
    print "<rect x='$x' y='0' height='$height' width='$ip_width' fill='$color'/>";
}

for (my $t = $min_time - ($min_time % 86400); $t < $max_time; $t += 8*3600) {
    my $y = timestamp_to_y $t;
    my $h = ($t % 86400 ? 1 : 3);
    print "<rect x='0' y='$y' height='$h' width='$width' fill='#666'/>";    
}

for my $record (@records) {
    draw_record $record;
}

print "</svg>";
