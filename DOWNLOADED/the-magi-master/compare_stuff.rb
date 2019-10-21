require_relative 'Score'

score_deltas = {}

divisions = ['ms', 'all-service', 'open']

divisions.each do |division|
  deltas = 0
  total_score_offsets_positive = 0
  score_offsets_positive = 0

  positive_warn_t = 0
  positive_warn_m = 0

  total_score_offsets_negative = 0
  score_offsets_negative = 0

  negative_warn_t = 0
  negative_warn_m = 0

  Score.where(division: division).each do |score|
    if score.r1_score != score.r1_o_score
      next if score.r1_score == nil
      next if score.r1_o_score == nil
      deltas += 1
      changes = score.r1_o_score - score.r1_score
      # If positive, CPOC added points back
      # If negative, CPOC subtracted points
      if changes < 0
        total_score_offsets_negative += changes * -1
        score_offsets_negative += 1

        negative_warn_m += 1 if score.warned_multi
        negative_warn_t += 1 if score.warned_time

        puts "Negative offset of #{score.team_id} (time: #{score.time.strip}, m?: #{score.warned_multi}) (scrape: #{score.r1_score}, official: #{score.r1_o_score}): #{changes}"
        puts "#{score.team_id},#{score.state},#{score.time.strip},#{score.r1_score},#{score.r1_o_score},#{score.warned_multi},#{score.warned_time},#{changes}"
      else
        total_score_offsets_positive += changes
        score_offsets_positive += 1

        positive_warn_m += 1 if score.warned_multi
        positive_warn_t += 1 if score.warned_time
        puts "Positive offset of #{score.team_id} (time: #{score.time.strip}, m?: #{score.warned_multi}) (scrape: #{score.r1_score}, official: #{score.r1_o_score}): #{changes}"
        puts "#{score.team_id},#{score.state},#{score.time.strip},#{score.r1_score},#{score.r1_o_score},#{score.warned_multi},#{score.warned_time},#{changes}"
      end
    end
  end

  begin
    average_neg = total_score_offsets_negative / score_offsets_negative
    average_pos = total_score_offsets_positive / score_offsets_positive
  rescue
  end
  puts "Division: #{division}"
  puts "Average negative changes: #{average_neg} (total negative delta teams: #{score_offsets_negative})."
  puts "Average positive changes: #{average_pos} (total positive delta teams: #{score_offsets_positive})."
  puts "Scores that were reduced with multiple instances flag: #{negative_warn_m}."
  puts "Scores that were reduced with time flag: #{negative_warn_t}."
  puts "Scores that were increased with multiple instances flag: #{positive_warn_m}."
  puts "Scores that were increased with time flag: #{positive_warn_t}."
end