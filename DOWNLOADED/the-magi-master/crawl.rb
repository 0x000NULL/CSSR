require 'nokogiri'
require 'open-uri'
require 'pry'
require 'mongo_mapper'
require 'active_support'
require 'active_support/core_ext'
require_relative 'Score'
MongoMapper.setup({'production' => {'uri' => ENV['MONGODB_URI']}}, 'production')

def crawl_now
  begin
    @document = Nokogiri::HTML(open("http://scoreboard.uscyberpatriot.org/"))
  rescue
    puts "Failed to connect to CCS's live output system."
    return nil
  end
  @nodeset = @document.css("tr.clickable") # @document.xpath("//tr")

  @nodeset.each do |row|
    if row.children[0].children[0].to_s.include? "CPOC" # CPOC is the CyberPatriot Operation Center (CPOC, CPOC_gol, CPOC_pla, CPOC_sil)
      # next
    end
    team_score = {
      :id => row.children[0].children[0].to_s, 
      :division => row.children[2].children[0].to_s, 
      :state => row.children[1].children[0].to_s,
      :images => row.children[4].children[0].to_s.to_i,
      :time => row.children[5].children[0].to_s,
      :score => row.children[6].children[0].to_s.to_i,
      :warnings => row.children[7].children[0].to_s,
      :tier => row.children[3].children[0].to_s
    }

    division = team_score[:division].downcase

    if division.include?('open')
      division = 'open'
    elsif division.include?('service')
      division = 'all-service'
    elsif division.include?('middle')
      division = 'ms'
    end

    score = Score.where({:team_id => team_score[:id]}).first
    if (score == nil)
      new_score = Score.new({
        :team_id => team_score[:id],
        :division => division,
        :r1_score => 0,
        :r2_score => 0,
        :r3_score => team_score[:score],
        :r4_score => 0,
        :time => team_score[:time],
        :warnings => team_score[:warnings],
        :images => team_score[:images],
        :state => team_score[:state],
        :total_score => team_score[:score],
        :tier => team_score[:tier]
      })
      if new_score.save
        puts "Created a new team #{team_score[:id]} in #{team_score[:division]}."
      else
        puts "Failed to create new team #{team_score[:id]}"
      end
    else
      if score.division != division
        puts "Redefined #{score.team_id} from division #{score.division} to #{division}."
      end
      if score.r1_o_score == nil
        score.r1_o_score = 0
      end
      score.division = division
      score.state = team_score[:state]
      # score.state.downcase! if division == 'all-service'
      score.images = team_score[:images]
      score.time = team_score[:time]
      # score.r2_score = team_score[:score]
      score.r3_score = team_score[:score]
      score.warnings = team_score[:warnings]
      # score.total_score = score.r1_o_score + score.r2_score
      score.tier = team_score[:tier]
      if (score.save)
        # puts "Team is #{team_score[:id]}. They're at #{team_score[:score]} in #{team_score[:state]}'s #{team_score[:division]} (#{team_score[:tier]}) division."
      else
        puts "Failed to save #{team_score[:id]}."
      end
    end
  end
  puts "Crawl run ok."
  return true
end

def calculate_state_ranks
  locations = []
  divisions = ['open']
  tiers = ['Silver', 'Gold', 'Platinum']
  File.readlines('location_list.txt').each do |line|
    locations.push(line.strip!)
  end

  locations.each do |location|
    divisions.each do |division|
      tiers.each do |tier|
        
        score_count = Score.where({:division => division, :state => location, :tier => tier}).count
        # puts "Calculating #{location} / #{division} / #{tier} (#{score_count} teams)."
        scores = Score.where({:division => division, :state => location, :tier => tier}).sort(:r3_score.desc)

        advancement = 3
        rank = 1
        scores.each do |score|
          score.top3 = false
          if score.r3_score == 0 || score.r3_score == nil
            score.warned_multi_r3 = false
            score.warned_time_r3 = false
            score.top3 = false
            score.wildcard = false
            score.state_rank = nil
            score.save
            next
          end
          if advancement > 0
            score.top3 = true
            score.wildcard = false
          else
            score.top3 = false
          end
          advancement -= 1

          score.state_rank = rank
          rank += 1

          if score.warnings != nil
            if score.warnings.include?('M')
              score.warned_multi_r3 = true
            else
              score.warned_multi_r3 = false
            end

            if score.warnings.include?('T')
              score.warned_time_r3 = true
            else
              score.warned_time_r3 = false
            end
          else
            score.warned_multi_r3 = false
            score.warned_time_r3 = false
          end

          score.save

        end
      end
    end

    # Calculate remaining wildcard teams

    # Zero out all wildcards before we start
    # Hacky shim because otherwise we never de-assign wildcards who fall out
    # scores = Score.where(:wildcard => true)
    # scores.each do |score|
    #   score.wildcard = false
    #   score.save
    # end

    divisions.each do |division|
      tiers.each do |tier|
        wildcards = 45 if division == 'all-service'
        wildcards = 36 if division == 'open'
        scores = Score.where({:division => division, :tier => tier}).sort(:r3_score.desc)
        scores.each do |score|
          if wildcards == 0
            if score.wildcard == true
              score.wildcard = false
              score.save
            end
            next
          end

          if score.top3
            score.wildcard = false
            score.save
            next
          end

          if (score.r3_score == 0 || score.r3_score == nil)
            score.top3 = false
            score.wildcard = false
            score.save
            next
          end
          if (wildcards > 0)
            score.wildcard = true
            wildcards -= 1
            score.save
          end
        end
      end
    end
  end

  score_count = Score.where({:division => 'ms'}).count

  scores = Score.where({:division => 'ms'}).sort(:r3_score.desc)

  mst50_slots = (score_count * 0.5).round(0)
  mst50_slots_save = mst50_slots

  scores.each do |score|
    if mst50_slots > 0
      score.mst50 = true
      mst50_slots -= 1
    else
      score.mst50 = false
    end

    if score.warnings != nil
      if score.warnings.include?('M')
        score.warned_multi_r3 = true
      else
        score.warned_multi_r3 = false
      end

      if score.warnings.include?('T')
        score.warned_time_r3 = true
      else
        score.warned_time_r3 = false
      end
    else
      score.warned_multi_r3 = false
      score.warned_time_r3 = false
    end

    score.save
  end

  puts "Calculation of state ranks ok."
  puts Score.where({:wildcard => true, :division => 'open', :tier => 'Platinum'}).count
  puts Score.where({:wildcard => true, :division => 'all-service', :tier => 'Platinum'}).count
  puts Score.where({:wildcard => true, :division => 'open', :tier => 'Gold'}).count
  puts Score.where({:wildcard => true, :division => 'all-service', :tier => 'Gold'}).count
  puts Score.where({:wildcard => true, :division => 'open', :tier => 'Silver'}).count
  puts Score.where({:wildcard => true, :division => 'all-service', :tier => 'Silver'}).count

end

def calculate_rank_numbers
  divisions = ['all-service', 'ms', 'open']

  divisions.each do |division|
    scores = Score.where({:division => division}).sort(:r3_score.desc)

    rank = 1

    scores.each do |score|
      score.division_rank = rank
      rank += 1
      score.save
    end
  end

  scores = Score.where({:division.ne => 'ms'}).sort(:r3_score.desc)

  rank = 1

  scores.each do |score|
    score.global_rank = rank
    rank += 1
    score.save
  end

  puts "Calculation of rank numbers ok."

end

def calculate_platinums

  # Open division
  score_count = Score.where({:division => 'open'}).count

  scores = Score.where({:division => 'open'}).sort(:total_score.desc)

  plat_slots = (score_count * 0.3).round(0)
  plat_slots_save = plat_slots
  scores.each do |score|
    if plat_slots > 0 
      score.platinum = true
      plat_slots -= 1
    else
      score.platinum = false
    end

    if score.warnings != nil
      if score.warnings.include?('M')
        score.warned_multi_r2 = true
      else
        score.warned_multi_r2 = false
      end

      if score.warnings.include?('T')
        score.warned_time_r2 = true
      else
        score.warned_time_r2 = false
      end
    else
      score.warned_multi_r2 = false
      score.warned_time_r2 = false
    end

    score.save
  end

  # AS division

  categories = ['cap', 'afjrotc', 'mcjrotc', 'ajrotc', 'njrotc', 'nscc']

  categories.each do |category|
    score_count = Score.where({:state => category}).count

    scores = Score.where({:state => category}).sort(:total_score.desc)

    plat_slots = (score_count * 0.3).round(0)
    puts "Platinum slots in category #{category} is #{plat_slots}"
    plat_slots_save = plat_slots
    scores.each do |score|
      if plat_slots > 0 
        score.platinum = true
        plat_slots -= 1
      else
        score.platinum = false
      end

      if score.warnings != nil
        if score.warnings.include?('M')
          score.warned_multi_r2 = true
        else
          score.warned_multi_r2 = false
        end

        if score.warnings.include?('T')
          score.warned_time_r2 = true
        else
          score.warned_time_r2 = false
        end
      else
        score.warned_multi_r2 = false
        score.warned_time_r2 = false
      end

      score.save
    end
  end

  puts "Calculation of platinums ok."

  score_count = Score.where({:division => 'ms'}).count

  scores = Score.where({:division => 'ms'}).sort(:total_score.desc)

  mst50_slots = (score_count * 0.5).round(0)
  mst50_slots_save = mst50_slots

  scores.each do |score|
    if mst50_slots > 0
      score.mst50 = true
      mst50_slots -= 1
    else
      score.mst50 = false
    end

    if score.warnings != nil
      if score.warnings.include?('M')
        score.warned_multi_r2 = true
      else
        score.warned_multi_r2 = false
      end

      if score.warnings.include?('T')
        score.warned_time_r2 = true
      else
        score.warned_time_r2 = false
      end
    else
      score.warned_multi_r2 = false
      score.warned_time_r2 = false
    end

    score.save
  end

  puts "Calculation of MST50 ok."
end

def calculate_national_finalists
  divisions = ['all-service', 'open', 'ms']

  divisions.each do |division|
    scores = Score.where({:division => division, :tier => 'Platinum'}).sort(:r4_score.desc)
    scores = Score.where({:division => division}).sort(:r4_score.desc) if division == 'ms'

    slots = 13
    slots = 4 if division == 'ms'

    scores.each do |score|
      score.nf = true if slots > 1
      slots -= 1 if slots >= 1
      # puts slots if slots != 0
      score.nf = false if slots == 0

      score.save
    end
  end

  scores = Score.all

  scores.each do |score|
    if score.warnings != nil
      # puts "Warnings not nil for team #{score.team_id}"
      if score.warnings.include?('M')
        score.warned_multi_r4 = true
      else
        score.warned_multi_r4 = false
      end

      if score.warnings.include?('T')
        score.warned_time_r4 = true
      else
        score.warned_time_r4 = false
      end
    else
      score.warned_multi_r4 = false
      score.warned_time_r4 = false
    end

    score.save
  end

  puts "Calculation of national finalists ok."
end

# binding.pry

