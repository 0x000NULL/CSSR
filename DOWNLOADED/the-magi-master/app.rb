require 'sinatra'
require 'active_support'
require 'active_support/core_ext'
require_relative 'Score'

class Magi < Sinatra::Base

  get '/rhs/?' do
    redirect to('/teams/08-0001,08-0002,08-0003,08-0004,08-0005,08-0117,08-0118,08-0119')
  end

  get '/all/?' do
    score_count = Score.where({:division.ne => 'ms'}).count

    scores = Score.where({:division.ne => 'ms'}).sort(:r3_score.desc)

    plat_slots = 0
    last_update = Score.where({:team_id => "09-0235"}).first.updated_at
    erb :div_platinum, :locals => {:last_update => last_update, :plat_slots => plat_slots, :mst50_slots => 0, :scores => scores, :teams => score_count, :division => 'all', :state => 'all'}
    
    # erb :div_platinum, :locals => {:last_update => last_update, :plat_slots => plat_slots, :scores => scores, :teams => score_count, :division => "N/A", :state => params[:state]}
  end

  get '/best/?' do
    scores = Score.where(:$or => [{:top3 => true, :tier => 'Platinum'}, {:wildcard => true, :tier => 'Platinum'}, {:mst50 => true}]).sort(:r3_score.desc)
    score_count = scores.count
    last_update = Score.where({:team_id => "09-0235"}).first.updated_at
    erb :div_platinum, :locals => {:last_update => last_update, :plat_slots => 0, :mst50_slots => 0, :scores => scores, :teams => score_count, :division => 'best', :state => 'all'}
  end

  get '/stars/?' do
    scores = Score.where({:star => true}).sort(:r3_score.desc)
    score_count = scores.count
    last_update = Score.where({:team_id => "09-0235"}).first.updated_at
    erb :div_platinum, :locals => {:last_update => last_update, :plat_slots => 0, :mst50_slots => 0, :scores => scores, :teams => score_count, :division => 'best', :state => 'all'}
  end

  get '/:division/?' do
    unless params[:division] == 'all-service' || params[:division] == 'open' || params[:division] == 'ms'
      return erb :error, :locals => {:error => "Invalid division specified. Must either be 'open', 'middle', or 'all-service'."}
    end

    if params[:tier] == 'Platinum' || params[:tier] == 'Silver' || params[:tier] == 'Gold'
      score_count = Score.where({:division => params[:division], :tier => params[:tier]}).count

      scores = Score.where({:division => params[:division], :tier => params[:tier]}).sort(:r3_score.desc)
    else
      score_count = Score.where({:division => params[:division]}).count

      scores = Score.where({:division => params[:division]}).sort(:r3_score.desc)
    end

    plat_slots = (score_count * 0.3).round(0)
    mst50_slots = (score_count * 0.5).round(0)

    plat_slots = 0 if params[:division] == 'ms'
    mst50_slots = 0 unless params[:division] == 'ms'

    if params[:division] == 'all-service'
      categories = ['cap', 'afjrotc', 'mcjrotc', 'ajrotc', 'njrotc', 'nscc']

      plat_slots = ""
      categories.each do |category|
        plat_slots += "#{(Score.where({:state => category}).count * 0.3).round(0)} in #{category}; "
      end
    end

    last_update = Score.where({:team_id => "09-0235"}).first.updated_at

    erb :div_platinum, :locals => {:last_update => last_update, :plat_slots => plat_slots, :mst50_slots => mst50_slots, :scores => scores, :teams => score_count, :division => params[:division], :state => params[:state]}
  end

  get '/' do
    erb :select_division
  end

  configure do
    MongoMapper.setup({'production' => {'uri' => ENV['MONGODB_URI']}}, 'production')
  end

  get '/team/:teamid/?' do
    scores = Score.where({:team_id => params[:teamid]}).sort(:r3_score.desc)

    if scores.count == 0
      return erb :error, :locals => {:error => "Invalid team ID specified. Team must be a fully qualified ID, e.g. 07-0152."}
    end
    last_update = Score.where({:team_id => params[:teamid]}).first.updated_at
    erb :team, :locals => {:scores => scores, :division => scores.first.division, :state => scores.first.state, :last_update => last_update}
  end

  get '/teams/:teamids/?' do

    unless (params[:teamids].include?(','))
      return erb :error, :locals => {:error => "Invalid team CSV specified. Separate TeamIDs by commas."}
    end

    teams = Array.new
    params[:teamids].split(',').each do |team|
      sc = Score.where({:team_id => team}).sort(:r3_score.desc).first

      unless sc == nil
        teams.push(sc)
      end
    end

    teams.sort! { |a, b| b.r3_score <=> a.r3_score }

    if teams.count == 0
      return erb :error, :locals => {:error => "Invalid team IDs specified. Teams must be fully qualified, e.g. 07-0152,06-0238, etc."}
    end

    last_update = teams[0].updated_at
    erb :teams, :locals => {:teams => teams, :last_update => last_update}
  end

  get '/:state/:division/?' do
    state = params[:state]
    if state.include?('_')
      state['_'] = ' '
    end
    score_count = Score.where({:division => params[:division], :state => params[:state]}).count

    if score_count == 0
      return erb :error, :locals => {:error => 'Invalid state / division combo specified. No data found.'}
    end

    teams = Score.where({:division => params[:division], :state => params[:state]}).sort(:r3_score.desc)

    erb :teams, :locals => {:teams => teams}
  end

  get '/:state/:division/:tier/?' do
    state = params[:state]
    if state.include?('_')
      state['_'] = ' '
    end
    score_count = Score.where({:division => params[:division], :state => params[:state], :tier => params[:tier]}).count

    if score_count == 0
      return erb :error, :locals => {:error => 'Invalid state / division combo specified. No data found.'}
    end

    teams = Score.where({:division => params[:division], :state => params[:state], :tier => params[:tier]}).sort(:r3_score.desc)

    erb :teams, :locals => {:teams => teams}
  end

end