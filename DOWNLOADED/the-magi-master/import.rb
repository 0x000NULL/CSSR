require 'active_support'
require 'active_support/core_ext'
require 'mongo_mapper'
require_relative './Score'
MongoMapper.setup({'production' => {'uri' => ENV['MONGODB_URI']}}, 'production')

# File.readlines('cp8_scores/allservice_round1.txt').each do |line|
#   line_parsed = line.split ' '
#   score = Score.where({:team_id => line_parsed[0]}).first

#   if score != nil
#     score.r1_o_score = line_parsed[2].to_i
#     score.total_score = score.r1_o_score
#     score.state = line_parsed[1].to_s
#   else
#     score = Score.new({
#       :team_id => line_parsed[0].to_s,
#       :r1_o_score => line_parsed[2].to_i,
#       :total_score => line_parsed[2].to_i,
#       :state => line_parsed[1].to_s,
#       :division => 'all-service'
#     })
#     puts "Created a new team #{line_parsed[0]}."
#   end
#   if score.save
#     puts "Stored #{line_parsed[0]} from all service at #{line_parsed[2]}."
#   else
#     puts "Failed to save #{line_parsed[0]}."
#   end
# end

# File.readlines('cp8_scores/open_round1.txt').each do |line|
#   line_parsed = line.split ' '
#   score = Score.where({:team_id => line_parsed[0]}).first

#   if score != nil
#     score.r1_o_score = line_parsed[1].to_i
#     score.total_score = score.r1_o_score
#   else
#     score = Score.new({
#       :team_id => line_parsed[0].to_s,
#       :r1_o_score => line_parsed[1].to_i,
#       :total_score => line_parsed[1].to_i,
#       :division => 'open'
#     })
#     puts "Created a new team #{line_parsed[0]}."
#   end
#   if score.save
#     puts "Stored #{line_parsed[0]} from open at #{line_parsed[1]}."
#   else
#     puts "Failed to save #{line_parsed[0]}."
#   end
# end

# File.readlines('results.csv').each do |line|
#   line_parsed = line.split ','
#   score = Score.where({:team_id => line_parsed[0]}).first

#   if score != nil
#     score.r3_score = line_parsed[5].to_f
#     score.state = line_parsed[1].to_s
#     score.tier = line_parsed[2].to_s
#   else
#     score = Score.new({
#       :team_id => line_parsed[0].to_s,
#       :r3_score => line_parsed[5].to_f,
#       :state => line_parsed[1].to_s,
#       :tier => line_parsed[2].to_s,
#     })
#     puts "Created a new team #{line_parsed[0]}."
#   end
#   if score.save
#     puts "Stored #{line_parsed[0]} from open at #{line_parsed[5]}."
#   else
#     puts "Failed to save #{line_parsed[0]}."
#   end
# end

File.readlines('cp9_tids.txt').each do |line|
  score = Score.where({:team_id => line.strip}).first

  if score == nil
    score = Score.new({
      :team_id => line.strip.to_s,
      :star => true
    })
    score.save
  else
    score.star = true
    score.save
  end
end

# File.readlines('cp7_r3_advancement_open.txt').each do |line|
#   line_parsed = line.split ','
#   score = Score.where({:team_id => line_parsed[0]}).first
#   if score == nil
#     score = Score.new({
#       :team_id => line_parsed[0],
#       :r1_score => 0,
#       :r2_score => 0,
#       # :r3_score => line_parsed[4],
#       :division => 'open',
#       :wildcard => false,
#       :top3 => false,
#       :tier => line_parsed[2],
#       :state_finalist => (line_parsed[6].include?('Advances to Regional Round') ? true : false)
#     })
#   else
#     score.state_finalist = line_parsed[6].include?('Advances to Regional Round') ? true : false
#   end
#   if score.save
#     puts "Stored #{score.team_id} from Open; Advancement: #{score.state_finalist}."
#   else
#     puts "Failed to save #{line_parsed[0]}."
#   end
# end