require 'camping/db'

module CASServer::Models
  
  module Consumable
    def consume!
      self.consumed = Time.now
      self.save!
    end
  end
  
  class Ticket < Base
    self.abstract_class = true
    def to_s
      ticket
    end
    
    def self.cleanup_expired(expiry_time, cleanup_interval_time = nil)
      if cleanup_interval_time
        unless maxiumum(:created_on) > Time.now + cleanup_interval_time
          $LOG.debug("Skipping cleanup of expired tickets for #{self} because"+
            " cleanup interval time has not yet been reached.")
          return false
        end
      end
    
      expired_tickets = find(:all, 
        :conditions => ["created_on > ?", Time.now + expiry_time])
        
      $LOG.info("Destroying #{expired_tickets.count} expired #{self} tickets.")
        
      expired_tickets.each do |t|
        t.destroy!
      end
    end
  end
  
  class LoginTicket < Ticket
    include Consumable
  end
  
  class ServiceTicket < Ticket
    include Consumable
  end
  
  class ProxyTicket < ServiceTicket
    belongs_to :proxy_granting_ticket
  end
  
  class TicketGrantingTicket < Ticket
  end
  
  class ProxyGrantingTicket < Ticket
    belongs_to :service_ticket
  end
  
  class Error
    attr_reader :code, :message
    
    def initialize(code, message)
      @code = code
      @message = message
    end
    
    def to_s
      message
    end
  end

  class CreateCASServer < V 0.1
    def self.up
      $LOG.info("Migrating database")
      
      create_table :casserver_login_tickets, :force => true do |t|
        t.column :ticket,     :string,   :null => false
        t.column :created_on, :timestamp, :null => false
        t.column :consumed,   :datetime, :null => true
        t.column :client_hostname, :string, :null => false
      end
    
      create_table :casserver_service_tickets, :force => true do |t|
        t.column :ticket,     :string,    :null => false
        t.column :service,    :string,    :null => false
        t.column :created_on, :timestamp, :null => false
        t.column :consumed,   :datetime, :null => true
        t.column :client_hostname, :string, :null => false
        t.column :username,   :string,  :null => false
        t.column :type,       :string,   :null => false
        t.column :proxy_granting_ticket_id, :integer, :null => true
      end
      
      create_table :casserver_ticket_granting_tickets, :force => true do |t|
        t.column :ticket,     :string,    :null => false
        t.column :created_on, :timestamp, :null => false
        t.column :client_hostname, :string, :null => false
        t.column :username,   :string,    :null => false
      end
      
      create_table :casserver_proxy_granting_tickets, :force => true do |t|
        t.column :ticket,     :string,    :null => false
        t.column :created_on, :timestamp, :null => false
        t.column :client_hostname, :string, :null => false
        t.column :iou,        :string,    :null => false
        t.column :service_ticket_id, :integer, :null => false
      end
    end
    
    def self.down
      drop_table :casserver_service_tickets
      drop_table :casserver_login_tickets
    end
  end
end