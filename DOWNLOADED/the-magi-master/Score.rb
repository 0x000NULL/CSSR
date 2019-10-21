require 'active_support'
require 'active_support/core_ext'
require 'mongo_mapper'
MongoMapper.setup({'production' => {'uri' => ENV['MONGODB_URI']}}, 'production')

class Score
  include MongoMapper::Document

  key :team_id, String, :unique => true
  key :r1_score, Integer # Round 1 crawled score
  key :r1_o_score, Integer # Round 1 official score
  key :r2_score, Integer # Round 2 crawled score
  key :r2_o_score, Integer # Round 2 official score
  key :r3_score, Float # Round 3 crawled score
  key :r3_o_score, Integer # Round 3 official score
  key :r4_score, Integer # Round 4 score
  key :r4_o_score, Integer # Round 4 official score
  key :total_score, Integer # Total score (from combined rounds)
  key :division, String # Division
  key :state, String # State or all service category
  key :images, Integer # Number of images
  key :time, String # Time
  key :warnings, String # ???
  key :platinum, Boolean # Platinum prediction
  key :mst50, Boolean # MST50 prediction
  key :top3, Boolean # Top 3 prediction
  key :state_rank, Integer # State rank (calculated)
  key :wildcard, Boolean # Wildcard (calculated)
  key :warned_time, Boolean # Were they warned on the score page for exceeding time?
  key :warned_multi, Boolean # Were they warned on the score page for having multiple instances open?
  key :warned_time_r2, Boolean
  key :warned_time_r3, Boolean
  key :warned_multi_r2, Boolean
  key :warned_multi_r3, Boolean
  key :warned_time_r4, Boolean
  key :warned_multi_r4, Boolean
  key :score_withheld, Boolean # Did CPOC withhold the score?
  key :score_review, Boolean # Did CPOC mark the score for review?
  key :notes, String # Notes about weird teams/scores
  key :tier, String # What tier are they?
  key :state_finalist, Boolean # Are they a state finalist?

  key :division_rank, Integer
  key :global_rank, Integer

  key :locked, Boolean # Is the score not supposed to go up?

  key :star, Boolean

  key :nf, Boolean
  Score.ensure_index(:team_id)
  Score.ensure_index(:state)
  Score.ensure_index(:division)
  timestamps!
end