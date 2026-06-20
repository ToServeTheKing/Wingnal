using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Wingnal
{
    /// <summary>Picks the message-bubble template or the day-separator template for items in the thread.</summary>
    public sealed partial class ChatItemTemplateSelector : DataTemplateSelector
    {
        public DataTemplate? MessageTemplate { get; set; }
        public DataTemplate? SeparatorTemplate { get; set; }

        protected override DataTemplate? SelectTemplateCore(object item) =>
            item is DaySeparatorItem ? SeparatorTemplate : MessageTemplate;

        protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container) =>
            SelectTemplateCore(item);
    }
}
