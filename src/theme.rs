//! Look and feel: a modern take on classic Windows. Raised buttons and column
//! headers, sunken tables, gradient caption bars and etched group boxes, in
//! Segoe UI and Consolas from the system font folder at the normal text size.
//! Three palettes; the choice is saved in settings and applies immediately.
//!
//! Everything degrades to plain egui when no theme has been applied (tests).

use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Id, Margin, Painter, Rect, Response,
    Sense, Shadow, Stroke, TextStyle, Ui, emath::GuiRounding, epaint::Mesh, pos2, vec2,
};
use ntsentry::settings::Theme;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const SEMIBOLD: &str = "semibold";

/// Whether the light palette is active, for colours chosen outside a `Ui`.
static LIGHT: AtomicBool = AtomicBool::new(false);

pub fn is_light() -> bool {
    LIGHT.load(Ordering::Relaxed)
}

/// Colours of one theme. `hi` and `lo` are the light and dark bevel lines,
/// `edge` the outer outline, `well` the background of lists and text boxes.
#[derive(Clone, Copy)]
struct Palette {
    dark: bool,
    face: Color32,
    face_hover: Color32,
    face_down: Color32,
    hi: Color32,
    lo: Color32,
    edge: Color32,
    well: Color32,
    stripe: Color32,
    row_hover: Color32,
    text: Color32,
    strong: Color32,
    weak: Color32,
    selection: Color32,
    selection_text: Color32,
    accent: Color32,
    caption: (Color32, Color32),
    caption_off: (Color32, Color32),
    caption_off_text: Color32,
}

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

fn palette_of(theme: Theme) -> Palette {
    match theme {
        Theme::Slate => Palette {
            dark: true,
            face: rgb(0x29313b),
            face_hover: rgb(0x313a46),
            face_down: rgb(0x20262e),
            hi: rgb(0x48525f),
            lo: rgb(0x12161b),
            edge: rgb(0x080a0d),
            well: rgb(0x1a2028),
            stripe: rgb(0x1e252e),
            row_hover: rgb(0x23384a),
            text: rgb(0xe8eef5),
            strong: Color32::WHITE,
            weak: rgb(0x8f9caa),
            selection: rgb(0x1f7a8c),
            selection_text: Color32::WHITE,
            accent: rgb(0x6fd3e6),
            caption: (rgb(0x0b3b47), rgb(0x2a93a8)),
            caption_off: (rgb(0x3b4552), rgb(0x5b6876)),
            caption_off_text: rgb(0xdfe6ee),
        },
        Theme::Charcoal => Palette {
            dark: true,
            face: rgb(0x2f3033),
            face_hover: rgb(0x37383c),
            face_down: rgb(0x26272a),
            hi: rgb(0x505257),
            lo: rgb(0x17181a),
            edge: rgb(0x0b0b0c),
            well: rgb(0x1f2022),
            stripe: rgb(0x242527),
            row_hover: rgb(0x2d3a4f),
            text: rgb(0xececec),
            strong: Color32::WHITE,
            weak: rgb(0x9a9ca0),
            selection: rgb(0x2457c5),
            selection_text: Color32::WHITE,
            accent: rgb(0x8fc8ff),
            caption: (rgb(0x0d2a6b), rgb(0x3a72d8)),
            caption_off: (rgb(0x45474c), rgb(0x6a6d73)),
            caption_off_text: rgb(0xe0e0e0),
        },
        Theme::Light => Palette {
            dark: false,
            face: rgb(0xe2e0db),
            face_hover: rgb(0xebe9e5),
            face_down: rgb(0xd4d2cc),
            hi: rgb(0xffffff),
            lo: rgb(0xa29f98),
            edge: rgb(0x64625e),
            well: rgb(0xffffff),
            stripe: rgb(0xf5f5f2),
            row_hover: rgb(0xdce7f7),
            text: rgb(0x121212),
            strong: Color32::BLACK,
            weak: rgb(0x6d6b66),
            selection: rgb(0x2457c5),
            selection_text: Color32::WHITE,
            accent: rgb(0x1f5aa0),
            caption: (rgb(0x0d2a6b), rgb(0x3a72d8)),
            caption_off: (rgb(0x8d8b86), rgb(0xb9b7b1)),
            caption_off_text: rgb(0xf4f4f4),
        },
    }
}

fn palette_id() -> Id {
    Id::unique("ntsentry_theme_palette")
}

fn palette(ui: &Ui) -> Option<Palette> {
    ui.ctx().data(|d| d.get_temp(palette_id()))
}

/// Loads Segoe UI and Consolas ahead of egui's bundled fonts, which stay as
/// fallbacks for symbols. Missing files leave the bundled fonts in place.
pub fn install_fonts(ctx: &egui::Context) {
    let folder = ntsentry::winutil::windows_directory().map(|w| format!("{w}\\Fonts"));
    let load = |file: &str| folder.as_ref().and_then(|f| std::fs::read(format!("{f}\\{file}")).ok());
    let mut fonts = FontDefinitions::default();
    let add_first = |fonts: &mut FontDefinitions, name: &str, file: &str, family: FontFamily| {
        if let Some(bytes) = load(file) {
            fonts.font_data.insert(name.to_string(), Arc::new(FontData::from_owned(bytes)));
            fonts.families.entry(family).or_default().insert(0, name.to_string());
        }
    };
    add_first(&mut fonts, "Segoe UI", "segoeui.ttf", FontFamily::Proportional);
    add_first(&mut fonts, "Consolas", "consola.ttf", FontFamily::Monospace);
    // Semibold for captions, column headers and the active tab; regular if absent.
    let regular = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    fonts.families.insert(FontFamily::Name(SEMIBOLD.into()), regular);
    add_first(&mut fonts, "Segoe UI Semibold", "seguisb.ttf", FontFamily::Name(SEMIBOLD.into()));
    ctx.set_fonts(fonts);
    ctx.data_mut(|d| d.insert_temp(Id::unique(SEMIBOLD), true));
}

/// Body-sized semibold, or regular when the fonts were not installed.
fn semibold(ui: &Ui) -> FontId {
    let size = TextStyle::Body.resolve(ui.style()).size;
    if ui.ctx().data(|d| d.get_temp::<bool>(Id::unique(SEMIBOLD))).unwrap_or(false) {
        FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
    } else {
        FontId::proportional(size)
    }
}

/// Applies a theme now and remembers its palette for the drawing helpers below.
pub fn apply(ctx: &egui::Context, theme: Theme) {
    let p = palette_of(theme);
    LIGHT.store(!p.dark, Ordering::Relaxed);
    let slot = if p.dark { egui::Theme::Dark } else { egui::Theme::Light };
    let mut style = (*ctx.style_of(slot)).clone();
    style.visuals = visuals(&p);
    style.spacing.button_padding = vec2(8.0, 2.0);
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    ctx.set_style_of(slot, style);
    ctx.set_theme(slot);
    ctx.data_mut(|d| d.insert_temp(palette_id(), p));
}

fn visuals(p: &Palette) -> egui::Visuals {
    let mut v = if p.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    let hard_shadow = |offset: i8| Shadow { offset: [offset, offset], blur: 0, spread: 0, color: Color32::from_black_alpha(90) };
    v.panel_fill = p.face;
    v.window_fill = p.face;
    v.window_stroke = Stroke::new(1.0, p.edge);
    v.window_corner_radius = CornerRadius::ZERO;
    v.menu_corner_radius = CornerRadius::ZERO;
    v.window_shadow = hard_shadow(4);
    v.popup_shadow = hard_shadow(3);
    v.extreme_bg_color = p.well;
    v.text_edit_bg_color = Some(p.well);
    v.code_bg_color = p.well;
    v.faint_bg_color = p.stripe;
    v.hyperlink_color = p.accent;
    v.weak_text_color = Some(p.weak);
    v.selection.bg_fill = p.selection;
    v.selection.stroke = Stroke::new(1.0, p.selection_text);
    let w = &mut v.widgets;
    // Labels and separators.
    w.noninteractive.bg_fill = p.face;
    w.noninteractive.weak_bg_fill = p.face;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.lo);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    // Buttons use weak_bg_fill; checkboxes and text boxes use bg_fill.
    w.inactive.weak_bg_fill = p.face;
    w.inactive.bg_fill = p.well;
    w.inactive.bg_stroke = Stroke::new(1.0, p.edge);
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    // bg_fill here is also the table row hover colour.
    w.hovered.weak_bg_fill = p.face_hover;
    w.hovered.bg_fill = p.row_hover;
    w.hovered.bg_stroke = Stroke::new(1.0, p.accent);
    w.hovered.fg_stroke = Stroke::new(1.5, p.strong);
    w.active.weak_bg_fill = p.face_down;
    w.active.bg_fill = p.face_down;
    w.active.bg_stroke = Stroke::new(1.0, p.edge);
    w.active.fg_stroke = Stroke::new(2.0, p.strong);
    // An open menu's title is highlighted like a selection.
    w.open.weak_bg_fill = p.selection;
    w.open.bg_fill = p.face;
    w.open.bg_stroke = Stroke::new(1.0, p.edge);
    w.open.fg_stroke = Stroke::new(1.0, p.selection_text);
    for state in [&mut w.noninteractive, &mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
        state.corner_radius = CornerRadius::ZERO;
        state.expansion = 0.0;
    }
    v
}

/// Width of a bevel line: one physical pixel, two on high-DPI screens.
fn line_width(painter: &Painter) -> f32 {
    let ppp = painter.pixels_per_point();
    ppp.round().max(1.0) / ppp
}

/// Lines just inside `rect`: `top_left` on the top and left, `bottom_right` on the others.
fn bevel(painter: &Painter, rect: Rect, top_left: Color32, bottom_right: Color32) {
    let px = line_width(painter);
    let r = rect.round_to_pixels(painter.pixels_per_point());
    let fill = |min, max, color| painter.rect_filled(Rect::from_min_max(min, max), CornerRadius::ZERO, color);
    fill(r.left_top(), pos2(r.right(), r.top() + px), top_left);
    fill(r.left_top(), pos2(r.left() + px, r.bottom()), top_left);
    fill(pos2(r.left(), r.bottom() - px), r.right_bottom(), bottom_right);
    fill(pos2(r.right() - px, r.top()), r.right_bottom(), bottom_right);
}

/// Gives a widget raised 3D edges, pressed in while held and outlined on hover.
pub fn raise(ui: &Ui, response: &Response) {
    let Some(p) = palette(ui) else { return };
    if !ui.is_rect_visible(response.rect) {
        return;
    }
    let painter = ui.painter();
    let outline = if response.hovered() && response.enabled() { p.accent } else { p.edge };
    let (top_left, bottom_right) = if response.is_pointer_button_down_on() { (p.lo, p.hi) } else { (p.hi, p.lo) };
    bevel(painter, response.rect, outline, outline);
    bevel(painter, response.rect.shrink(line_width(painter)), top_left, bottom_right);
}

/// `ui.button` with raised edges.
pub fn button(ui: &mut Ui, text: impl Into<egui::WidgetText>) -> Response {
    let response = ui.button(text);
    raise(ui, &response);
    response
}

/// A raised button that is greyed out unless `enabled`.
pub fn button_enabled(ui: &mut Ui, enabled: bool, button: impl egui::Widget) -> Response {
    let response = ui.add_enabled(enabled, button);
    raise(ui, &response);
    response
}

/// Draws `add` in a sunken well with the list background, clipped to the well.
pub fn well<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let Some(p) = palette(ui) else { return add(ui) };
    let inner = egui::Frame::new().fill(p.well).inner_margin(2.0).show(ui, |ui| {
        ui.set_clip_rect(ui.max_rect().intersect(ui.clip_rect()));
        add(ui)
    });
    let painter = ui.painter();
    let rect = inner.response.rect;
    bevel(painter, rect, p.lo, p.hi);
    bevel(painter, rect.shrink(line_width(painter)), p.edge, p.face);
    inner.inner
}

/// Raised background for the table header cell being drawn in `ui`.
pub fn header_cell(ui: &Ui) {
    let Some(p) = palette(ui) else { return };
    let painter = ui.painter();
    let rect = ui.max_rect().expand2(0.5 * ui.spacing().item_spacing);
    painter.rect_filled(rect, CornerRadius::ZERO, p.face);
    bevel(painter, rect, p.hi, p.edge);
    bevel(painter, rect.shrink(line_width(painter)), p.face, p.lo);
}

/// Font for column header titles.
pub fn header_font(ui: &Ui) -> FontId {
    semibold(ui)
}

/// Full-width title bar with a horizontal gradient: accent colours when
/// `active`, grey otherwise.
pub fn caption(ui: &mut Ui, text: &str, active: bool) {
    let Some(p) = palette(ui) else {
        ui.strong(text);
        return;
    };
    let height = ui.text_style_height(&TextStyle::Body) + 6.0;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    let ((left, right), color) = if active { (p.caption, Color32::WHITE) } else { (p.caption_off, p.caption_off_text) };
    let mut mesh = Mesh::default();
    for (corner, c) in [(rect.left_top(), left), (rect.right_top(), right), (rect.right_bottom(), right), (rect.left_bottom(), left)] {
        mesh.colored_vertex(corner, c);
    }
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    let painter = ui.painter();
    painter.add(egui::Shape::mesh(mesh));
    painter.text(rect.left_center() + vec2(6.0, 0.0), Align2::LEFT_CENTER, text, semibold(ui), color);
}

/// A classic tab, raised on three sides. The selected one stands taller and
/// is semibold; lay tabs out in a row with no spacing between them.
pub fn tab(ui: &mut Ui, selected: bool, text: &str) -> Response {
    let Some(p) = palette(ui) else { return ui.selectable_label(selected, text) };
    let font = if selected { semibold(ui) } else { TextStyle::Body.resolve(ui.style()) };
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, Color32::PLACEHOLDER);
    let pad = vec2(10.0, 4.0);
    // Every tab takes the same height so their bottoms line up; unselected ones are drawn lower.
    let drop = if selected { 0.0 } else { 3.0 };
    let (rect, response) = ui.allocate_exact_size(galley.size() + 2.0 * pad, Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let px = line_width(painter);
        let r = Rect::from_min_max(rect.min + vec2(0.0, drop), rect.max).round_to_pixels(painter.pixels_per_point());
        let fill = |min, max, color| painter.rect_filled(Rect::from_min_max(min, max), CornerRadius::ZERO, color);
        fill(r.min, r.max, if selected { p.face } else { p.face_down });
        fill(r.left_top(), pos2(r.right(), r.top() + px), p.edge);
        fill(r.left_top(), pos2(r.left() + px, r.bottom()), p.edge);
        fill(pos2(r.right() - px, r.top()), r.right_bottom(), p.edge);
        fill(pos2(r.left() + px, r.top() + px), pos2(r.right() - px, r.top() + 2.0 * px), p.hi);
        fill(pos2(r.left() + px, r.top() + px), pos2(r.left() + 2.0 * px, r.bottom()), p.hi);
        fill(pos2(r.right() - 2.0 * px, r.top() + px), pos2(r.right() - px, r.bottom()), p.lo);
        if !selected {
            fill(pos2(r.left(), r.bottom() - px), r.right_bottom(), p.hi);
        }
        let color = if selected || response.hovered() { p.text } else { p.weak };
        painter.galley(rect.min + pad + vec2(0.0, drop / 2.0), galley, color);
    }
    response
}

/// Etched frame with `title` set into its top edge.
pub fn group_box<R>(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    let Some(p) = palette(ui) else {
        return egui::Frame::new()
            .fill(ui.visuals().faint_bg_color)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.strong(title);
                add(ui)
            })
            .inner;
    };
    let galley = ui.painter().layout_no_wrap(title.to_string(), semibold(ui), p.text);
    let title_height = galley.size().y;
    let margin = Margin { left: 8, right: 8, top: (title_height + 2.0) as i8, bottom: 8 };
    let inner = egui::Frame::new().inner_margin(margin).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        add(ui)
    });
    let rect = inner.response.rect;
    let painter = ui.painter();
    let frame = Rect::from_min_max(pos2(rect.left(), rect.top() + (title_height / 2.0).round()), rect.max);
    bevel(painter, frame, p.lo, p.hi);
    bevel(painter, frame.shrink(line_width(painter)), p.hi, p.lo);
    let title_rect = Rect::from_min_size(pos2(rect.left() + 6.0, rect.top()), galley.size() + vec2(6.0, 0.0));
    painter.rect_filled(title_rect, CornerRadius::ZERO, p.face);
    painter.galley(title_rect.min + vec2(3.0, 0.0), galley, p.text);
    inner.inner
}

/// One sunken status-bar segment.
pub fn status_cell<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let Some(p) = palette(ui) else { return add(ui) };
    let inner = egui::Frame::new().inner_margin(Margin::symmetric(6, 1)).show(ui, |ui| ui.horizontal(add).inner);
    bevel(ui.painter(), inner.response.rect, p.lo, p.hi);
    inner.inner
}
