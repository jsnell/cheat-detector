#!/usr/bin/perl -w

use strict;

use Date::Parse;
use JSON;
use Getopt::Long;
use Pod::Usage;

=pod

=head1 NAME

cheat-detector - Looks for suspicious patterns in online game move logs

=head1 SYNOPSIS

B<cheat-detector> S<[ B<--users-out file> ]> S<[ B<--pairs-out file> ]> S<[ B<--time-buckets-out file> ]> S<[ B<--bucket-seconds integer> ]> S<[ B<--help> ]> S<[ I<files> ]>

=head1 DESCRIPTION

Takes as input files with JSON format records (one per row), each
containing at least the following fields describing invidual moves in
a game:

=over 8

=item B<username>: The user who did the move

=item B<game>: The game / match the move was made in

=item B<timestamp>: Time (in YYYY-MM-DD hh:mm:ss format) the move was made

=item B<ip>: IP address the move was made from

=back

=head1 OPTIONS

=over 8

=item B<--help> Print verbose usage information.

=item B<--bucket-seconds integer> Size of time buckets, in seconds. Defaults
  to 1800.

=item B<--pairs-out> Output a CSV file containing for each suspicious pair
  of users the following information: a similarity score, the usernames,
  number of moves that matched and mismatched, and number of delays that
  matched and mismatched.

=item B<--time-buckets-out> Print a file containing JSON records, one
  per row, with the following information for each user / IP address
  pair at 30 minute intervals: the username, start of the time period,
  the IP address, number of moves by that user from that IP in that
  time. If the "delay" field is true, the user did not actually make a
  move. Instead it was their move in at least one match. The IP address
  matches the first IP from which the user made a move after this time.
  Records will only be output for users involved in at least one suspicious
  pair.

=back

=head1 ENVIRONMENT

No effect.

=head1 AUTHOR

Juho Snellman, <jsnell@iki.fi>

=head1 LICENSE

Standard MIT license

=cut
    
my $bucket_size = 1800;

# Do the IP sets contain at least one shared address?
sub ips_intersect {
    my ($set1, $set2) = @_;

    my $count = 0;
    my $match = 0;
    for my $key (keys %{$set1}) {
        # Ignore delay records
        next if $key eq 'delay';
        $count += $set1->{$key};
        if ($set2->{$key}) {
            return 1;
        }
    }

    return 0;
}

sub categorize_time_bucket {
    my ($set) = @_;
    my $count = keys %{$set};
    my ($move, $stall, $idle) = (0, $set->{delay}, $count);

    if ($stall) {
        $move = $count - 1;
    } else {
        $move = $count;
    }

    my $index = ($move ? 0 : ($stall ? 1 : 2));
    ($move, $stall, $idle, $index);
}

# Merge multiple hashes together. For duplicate keys, the output value
# will be the sum of all input values.
sub merge {
    my %res = ();
    for my $h (@_) {
        while (my ($k, $v) = each %{$h}) {
            $res{$k} += $v;
        }
    }

    \%res;
}

# Update the similarity score based on new samples. The 
sub update_similarity {
    my ($similarity, $weight, $sample_weight_factor,
        $pos_sample, $neg_sample) = @_;
    my $total_weight =
        $weight + ($pos_sample + $neg_sample) * $sample_weight_factor;
    
    $similarity = (1 * $pos_sample * $sample_weight_factor + 
                   0 * $neg_sample * $sample_weight_factor +
                   $similarity * $weight)
        / ($total_weight);

    ($similarity, $total_weight);
}

sub user_similarity {
    my ($user, $other) = @_;

    # Starting score. Arbitrary, but should be low enough that cases with
    # only few samples will not be flagged for manual inspection.
    my $similarity = 0;
    # Fairly low starting weight; we'd expect hundreds of samples for
    # interesting cases.
    my $similarity_weight = 20;
    # How many time slots in sequence have both players stalled on?
    my $delay_both_run = 0;

    for my $bucket (sort { $a cmp $b } keys %{$user->[1]}) {
        my $user_ips = $user->[1]{$bucket};
        my $other_ips = $other->[1]{$bucket};

        my $user_next = $user->[1]{$bucket + $bucket_size};
        my $user_prev = $user->[1]{$bucket - $bucket_size};

        my $other_prev = $other->[1]{$bucket - $bucket_size};
        my $other_next = $other->[1]{$bucket + $bucket_size};

        $user_ips = merge($user_ips, $user_next, $user_prev);
        $other_ips = merge($other_ips, $other_next, $other_prev);
            
        my ($user_moved, $user_delayed, $user_idle, $user_index) = categorize_time_bucket $user_ips;
        my ($other_moved, $other_delayed, $other_idle, $other_index) = categorize_time_bucket $other_ips;
        my $ips_intersect = ips_intersect merge($user_ips, $user_next, $user_prev), merge($other_ips, $other_next, $other_prev);
        my $move_value = $ips_intersect ? 10 + $delay_both_run : -10;
        my @scoring = ([$move_value, -5, 0],
                       [-1, 1, 0],
                       [0, 0, 0]);
        my $score = $scoring[$user_index][$other_index];
        
        $similarity += $score;
        $similarity_weight += abs $score;

        if ($user_delayed and $other_delayed) {
            $delay_both_run++;
        } else {
            $delay_both_run = 0;
        }
    }

    return [ ($similarity / $similarity_weight) / 2 + 0.5, # 0-1 range
             $user->[0],
             $other->[0] ];
}

sub user_time_buckets {
    my ($fh, $username, $user) = @_;
    my $last_ip = '';
    for my $bucket (sort { $b <=> $a } keys %{$user}) {
        my $user_ips = $user->{$bucket};
        while (my ($ip, $count) = each %{$user_ips}) {
            my $delay = 0;
            # Assign delay records the previous IP we saw. Since iteration
            # is in reverse time order, this actually means the next IP
            # that the user did a move from.
            if ($ip eq 'delay') {
                $ip = $last_ip;
                $delay = 1;
            } else {
                $last_ip = $ip;
            }
            print $fh encode_json { user => $username,
                                    timestamp => $bucket,
                                    ip => $ip,
                                    count => $count,
                                    delay => $delay }, "\n";
        }
    }
}

sub analyze {
    my ($pairs_out, $time_buckets_out) = @_;

    my %players = ();
    my %buckets = ();
    my %accept_player = ();

    my %last_action = ();
    my $first_hour;

    while (<>) {
        my $record = decode_json $_;
        next if !defined $record->{ip};
        next if !defined $record->{username};

        my $time = str2time($record->{timestamp_utc}) // die "Couldn't parse $record->{timestamp_utc}\n";

        my $bucket = $time - ($time % $bucket_size);
        $first_hour //= $bucket;

        my $username = $record->{username};
        my $ip = $record->{ip};

        $players{$username}{$bucket}{$ip}++;
        $accept_player{$username}++ if $record->{game} =~ /^4pLeague_/;

        if (defined $last_action{$record->{game}}) {
            for (my $prev = $bucket - $bucket_size;
                 $prev > $last_action{$record->{game}};
                 $prev -= $bucket_size) {
                last if exists $players{$username}{$prev};
                $players{$username}{$prev}{delay} = 1;
            }
        }

        $buckets{"$ip ".(int $time / 86400)}{$username}++;
        $last_action{$record->{game}} = $bucket;
    }

    my %candidate = ();

    while (my ($key, $users) = each %buckets) {
        my @users = keys %{$users};
        if (@users > 1) {
            for my $a (@users) {
                next if !$accept_player{$a};
                for my $b (@users) {
                    next if !$accept_player{$b};
                    next if $a eq $b;
                    $candidate{$a}{$b}++;
                }
            }
        }
    }

    my @scores = ();
    while (my ($user, $others) = each %candidate) {
        if ($pairs_out) {
            for my $other (keys %{$others}) {
                push @scores, user_similarity [$user, $players{$user}],
                                              [$other, $players{$other}];
            }
        }
        if ($time_buckets_out) {
            user_time_buckets $time_buckets_out, $user, $players{$user};
        }
    }
    
    if ($pairs_out) {
        print $pairs_out "similarity,user_a,user_b,match,mismatch,delay_match,delay_mismatch\n";
        for my $score (sort { $b->[0] <=> $a->[0] } @scores) {
            print $pairs_out join ",", @{$score};
            print $pairs_out "\n";
        }
    }
}

my ($pairs_out, $time_buckets_out) = @_;

sub open_or_die {
    my ($file) = @_;
    open my $fh, ">", $file or die "Couldn't open $file: $!";
    $fh;
}

if (!GetOptions("help" => sub { pod2usage -exitval => 0, -verbose => 2 },
                "bucket-seconds=i" => \$bucket_size,
                "pairs-out=s" => sub { $pairs_out = open_or_die $_[1] },
                "time-buckets-out=s" => sub {
                    $time_buckets_out = open_or_die $_[1]
                })) {
    pod2usage 1;
}

if (!($pairs_out || $time_buckets_out)) {
    print STDERR "Error: Must produce at least one kind of output file\n";
    pod2usage -exitval => 1;
}

analyze $pairs_out, $time_buckets_out;

