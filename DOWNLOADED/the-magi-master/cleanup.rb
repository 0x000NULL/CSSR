require_relative 'Score'

# Score.where({:wildcard => true, :top3 => true}).each do |score|
#   score.wildcard = false
#   score.save
# end

Score.all.each do |score|
  if score.division == 'all-service'
    score.top3 = false
    score.wildcard = false
    score.save
  end
end
