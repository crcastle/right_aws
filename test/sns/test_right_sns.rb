require File.dirname(__FILE__) + '/test_helper.rb'

class TestSns < Test::Unit::TestCase

  GRANTEE_EMAIL_ADDRESS = 'fester@example.com'
  RIGHT_MESSAGE_TEXT    = 'Right test message'

  
  def setup
    $stdout.sync = true
    @grantee_aws_id = '100000000001'
    @topic_name = 'right_sns_test_topic'
    @sns = RightAws::Sns.new(TestCredentials.aws_access_key_id, TestCredentials.aws_secret_access_key)
  end
    
  #---------------------------
  # RightAws::Sns
  #---------------------------

  def test_01_create_topic
    topic = @sns.create_topic @topic_name
    assert topic.kind_of?(RightAws::Sns::Topic), 'New topic wasn\'t initiated'
  end

  def test_02_list_topics
    topics = @sns.topics
    assert topics.kind_of?(Array), 'Must be an array'
    assert topics.length > 0, 'Must be more than 0 topics in list'
  end

  def test_03_set_and_get_topic_attributes
    topic = @sns.topics.last
    assert topic.owner, 'Unable to get the Owner attribute - get_topic_attributes fail'
    topic.display_name = 'Dave'
    assert_equal 'Dave', topic.display_name, 'Unable to set the DisplayName attribute - set_topic_attributes fail'
  end

  def test_04_add_permissions
    topic = @sns.topics.last
    assert topic.add_permission('test', @grantee_aws_id, 'Publish')
  end

  def test_05_test_permissions
    topic = @sns.topics.last
    assert !topic.policy.blank?
  end
  
  def test_06_remove_permissions
    topic = @sns.topics.last
    assert topic.remove_permission('test')
  end

  def test_07_send_message
    topic = @sns.topics.last
    message = topic.send_message(RIGHT_MESSAGE_TEXT, 'A subject')
    assert message, 'Message was not created'
  end
  
  #---------------------------
  # RightAws::SnsInterface
  #---------------------------

  def test_08_set_amazon_problems
    original_problems = RightAws::SnsInterface.amazon_problems
    assert(original_problems.length > 0)
    RightAws::SnsInterface.amazon_problems= original_problems << "A New Problem"
    new_problems = RightAws::SnsInterface.amazon_problems
    assert_equal(new_problems, original_problems)

    RightAws::SnsInterface.amazon_problems= nil
    assert_nil(RightAws::SnsInterface.amazon_problems)
  end  
end
