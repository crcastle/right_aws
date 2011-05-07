#
# Copyright (c) 2007-2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightAws

    #
    # = RightAws::Sns -- RightScale's Amazon SNS interface
    # The RightAws::Sns class provides a complete interface to Amazon's Simple
    # Notification Service.
    # For explanations of the semantics
    # of each call, please refer to Amazon's documentation at
    # http://docs.amazonwebservices.com/sns/2010-03-31/api/
    #
    # Error handling: all operations raise an RightAws::AwsError in case
    # of problems. Note that transient errors are automatically retried.
    #
    #  sns    = RightAws::Sns.new(aws_access_key_id, aws_secret_access_key)
    #  topics = sns.topics #=> [<Sns::Topic>, <Sns::Topic>]
    #  topic1 = sns.create_topic('bananas') #=> <Sns::Topic>
    #  topic1.subscribe('email', 'john@example.com') #=> true
    #   ...
    #  topic1.send_message('Some content', 'An optional subject')
    #       
    # Params is a hash:
    #
    #    {:server       => 'sns.us-east-1.amazonaws.com' # Amazon service host: 'sns.us-east-1.amazonaws.com' (default)
    #     :port         => 443                   # Amazon service port: 80 or 443 (default)
    #     :multi_thread => true|false            # Multi-threaded (connection per each thread): true or false (default)
    #     :signature_version => '0'              # The signature version : '0' or '1'(default)
    #     :logger       => Logger Object}        # Logger instance: logs to STDOUT if omitted }
    #
  class Sns
    attr_reader :interface
    
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      @interface = SnsInterface.new(aws_access_key_id, aws_secret_access_key, params)
    end
    
      # Retrieves a list of topics.
      # Returns an +array+ of +Topic+ instances.
      #
      #  RightAws::Sns.topics #=> array of topics
      #
    def topics
      @interface.list_topics.map do |arn|
        Topic.new(self, arn)
      end
    end
    
      # Returns Topic instance by ARN. 
    def topic(arn)
      Topic.new(self, arn)
    end
    
      # Creates a new topic.
    def create_topic(name)
      @interface.create_topic(self, name)
    end
  
    class Topic
      attr_reader :arn, :sns
        
        # Creates new Topic instance. 
        # Does not create a topic at Amazon.
        #
        #  topic = RightAws::Sns::Topic.new(sns, 'arn%3Aaws%3Asns%3Aus-east-1%3A123456789012%3AMy-Topic')
        #
      def initialize(sns, arn)
        @sns = sns
        @arn = arn
      end
      
        # Deletes queue. 
        # Queue must be empty or +force+ must be set to +true+. 
        # Returns +true+. 
        #
        #  queue.delete(true) #=> true
        #
      def delete
        @sns.interface.delete_topic(arn)
      end
      alias_method :destroy, :delete
      
        # Sends new message to topic. 
        # Returns new Message instance that has been sent to topic.
      def send_message(body, subject = nil)
        @sns.interface.send_message(arn, body, subject)
      end
      alias_method :push, :send_message
      
        # Returns the AWS account ID of the topic's owner
      def owner
        topic_attributes['Owner']
      end
      
        # Returns the JSON serialization of the topic's access control policy
      def policy
        unless !topic_attributes['Policy'] || topic_attributes['Policy'].length == 0
          JSON.parse(topic_attributes['Policy'])
        end
      end
      
        # Returns the human-readable name used in the "From" field for
        # notifications to email and email-json endpoints
      def display_name
        topic_attributes['DisplayName']
      end
      
        # Sets the display name
      def display_name=(value)
        set_topic_attribute('DisplayName', value)
      end
      
        # Returns a hash in the format:
        # { :set => [<Sns::Member>, <Sns::Member>, <Sns::Member>], :next => '123' }
        #
        # Accepts an optional next_token telling where to start from
      def subscriptions(next_token = nil)
        result = @sns.interface.list_subscriptions_by_topic(arn, next_token)
        SubscriptionListResponse.new(self, result[:members], result[:next_token])
      end
      
        # Returns a <Member> object
      def subscribe(protocol, end_point)
        raise StandardError, "Protocol (#{protocol}) is not valid" unless ['http', 'https', 'email', 'email-json', 'sqs']
        @sns.interface.subscribe_to_topic(arn, protocol, end_point)
      end
      
        # Gives another AWS account holder access to set actions within your account
      def add_permission(label, account_ids, actions)
        account_ids = [account_ids.to_s] unless account_ids.kind_of?(Array)
        actions     = [actions.to_s]     unless actions.kind_of?(Array)
        @sns.interface.add_permissions(arn, label, account_ids, actions)
      end
      
        # Removes permission from another AWS account holder
      def remove_permission(label)
        @sns.interface.remove_permissions(arn, label)
      end
      
        # Given a token, confirm the subscription on the topic
      def confirm_subscription(token, authenticate_on_unsubscribe = false)
        @sns.interface.confirm_subscription(arn, token, authenticate_on_unsubscribe)
      end

      private
      def set_topic_attribute(name, value)
        if @sns.interface.set_topic_attributes(arn, name, value)
          @topic_attributes     ||= {}
          @topic_attributes[name] = value
        end
      end
      
      def topic_attributes
        @topic_attributes ||= @sns.interface.get_topic_attributes(arn)
      end
    end
    
    class Message
      attr_reader :topic, :id, :body, :subject
      
      def initialize(topic, id = nil, body = nil, subject = nil)
        @topic       = topic
        @id          = id
        @body        = body
        @subject     = subject
      end
    end
    
    class SubscriptionListResponse
      attr_reader :topic, :next_token, :members
      
      def initialize(topic, members, next_token = nil)
        @topic = topic
        self.members = members
        @next_token = next_token
      end
      
      private
      
      def members=(members)
        if members.length > 0 && 
            members.all? { |member| member.is_a?(Member) }
          return @members = members 
        elsif members.any? { |member| member.is_a?(Member) }
          raise ArgumentError, "Mismatch on subscription members class types."
        else # Assume it's interface hash data for us to wrap
          @members = members.map { |member_data| Member.new(topic.sns, member_data) }
        end
      end
    end
    
    class Member
      attr_accessor :topic_arn, :protocol, :subscription_arn, :owner, :endpoint
      attr_reader :subscription, :sns_interface
      
      def initialize(sns, member_data)
        @sns_interface = sns.interface
        self.topic_arn = member_data['TopicArn']
        self.protocol = member_data['Protocol']
        self.subscription_arn = member_data['SubscriptionArn']
        self.owner = member_data['Owner']
        self.endpoint = member_data['Endpoint']
      end
      
      # def confirm(token, authenticate_on_unsubscribe = false)
      #   raise "A topic arn and token are required for confirmation." unless topic_arn && token
      #   sns_interface.confirm_subscription(topic_arn, token, authenticate_on_unsubscribe)
      # end
    
      def parse(text)
        # TODO?
        raise "not implemented"
      end
    end
    
  end
  
end